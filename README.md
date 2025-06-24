# 2FA Password Manager

A two-factor authentication password manager originally developed as a university project.  
It received full academic marks (15/15) and was later refactored to improve its GUI and functionality.

## Features

- AES-GCM, ChaCha20-Poly1305, and Fernet encryption
- SHA256, SHA512, and HMAC-SHA256 integrity verification
- GUI (Tkinter) for managing passwords and configurations
- Two-factor authentication (2FA) via email
- Per-user encryption and integrity settings
- Secure audit logging

## Installation

Requires Python 3.7+ and Linux/WSL.

```bash
pip install -r requirements.txt
```

## Running the Application

```bash
python3 2fa_client.py
```

## Security Notice

The email credentials (SMTP email and password) are hardcoded in the `Config` class.  
This is intentional for educational use only.

In a production environment, credentials should be securely managed using one of the following methods:

- Environment variables
- Encrypted configuration file
- `.env` file loaded with tools like `python-dotenv`

Additionally, for real-world 2FA solutions, internal implementation details (like encryption logic or code structure) should never be publicly exposed, to reduce the attack surface.

## Data Security Overview

- All user data is encrypted using a chosen algorithm (AES-GCM, ChaCha20-Poly1305, or Fernet)
- Encryption keys are derived using PBKDF2-HMAC-SHA256 with a per-user random salt
- Each password vault includes integrity verification
- All data is stored locally in JSON files (no cloud usage)

## File Structure

- `2fa_client.py` – main application
- `requirements.txt` – required dependencies
- `users.json`, `passwords.json`, `audit.log`, `user_configs.json` – created during runtime

## 2FA Mechanism

- A 6-digit verification code is sent via email (using Gmail SMTP)
- The code is valid for 5 minutes and required after successful password login
