# Chromium App-Bound Encryption (ABE) Research & Detection

## Overview
This repository contains research, telemetry, and detection engineering resources focused on Chromium's App-Bound Encryption (ABE).

App-Bound Encryption was introduced to protect sensitive browser data (such as cookies and saved passwords) by binding the encryption key to the application itself, making it significantly harder for external processes to decrypt the data using standard DPAPI mechanisms.

This repository is strictly for defensive research, detection engineering, and educational purposes. It does not contain weaponized extraction code.

## How to build
Setup rust using the Officle webside https://rust-lang.org
Go to the project directory.


Open cmd and run

```cargo build -r```

## Threat Model
Modern infostealers frequently target Chromium-based browsers (Chrome, Edge, Brave, Opera). Historically, these tools relied on extracting the encrypted_key from the Local State file and decrypting it via Windows DPAPI, followed by AES-256-GCM decryption of the credential databases (Cookies, Login Data).

With the rollout of ABE, the app_bound_encrypted_key is introduced alongside the standard encrypted_key. This new mechanism requires elevation and COM interfaces (specifically tied to the browser's internal processes) to unwrap the key, severely disrupting standard infostealer workflows.

## Detection Opportunities
Defenders can leverage the behavioral patterns of tools attempting to bypass or interact with ABE.

## File System Telemetry
Access to Local State: Monitor for non-browser processes reading Local State, specifically looking for parsing of os_crypt -> app_bound_encrypted_key.

Database Access: Monitor for unauthorized processes copying or reading Cookies or Login Data SQLite databases (often copied to %TEMP%).

Naming Conventions: Infostealers often use predictable naming patterns for temporary database copies (e.g., chromdec_<pid>_Cookies).

## API Monitoring
Monitor for calls to CryptUnprotectData (DPAPI) originating from non-standard executables.

Monitor for processes interacting with browser COM interfaces associated with elevation.

## Mitigation & Hardening
Ensure Chromium-based browsers are updated to the latest versions where ABE is enforced.

Restrict the execution of unauthorized binaries in user-writable directories.

Deploy Endpoint Detection and Response (EDR) rules to flag the mass-access of browser profile directories.

## Disclaimer
The information and resources provided in this repository are for educational and defensive purposes only. The author do not condone, support, or take responsibility for the misuse of this information or any damage caused by the application of these concepts.
