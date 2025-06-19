#!/usr/bin/env python3
"""
Password Manager with Two-Factor Authentication

A secure password management application featuring:
- Multiple encryption algorithms (AES-GCM, ChaCha20-Poly1305, Fernet)
- Email-based two-factor authentication
- Integrity verification (SHA256, SHA512, HMAC-SHA256)
- Comprehensive audit logging

Author: chmodxChironex
Version: 1.2.1
Python: 3.7+
"""

import os
import json
import hmac
import hashlib
import base64
import smtplib
import secrets
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, Tuple, Optional, Callable

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    CRYPTO_AVAILABLE = True
except ImportError:
    print("Error: cryptography library not found. Please install it with: pip install cryptography")
    CRYPTO_AVAILABLE = False


    class CryptographyPlaceholder:
        """Placeholder for missing cryptography components"""

        def __init__(self, *args, **kwargs):
            raise ImportError("Cryptography library not available")

        def derive(self, *args, **kwargs):
            raise ImportError("Cryptography library not available")

        def encrypt(self, *args, **kwargs):
            raise ImportError("Cryptography library not available")

        def decrypt(self, *args, **kwargs):
            raise ImportError("Cryptography library not available")


    Fernet = AESGCM = ChaCha20Poly1305 = PBKDF2HMAC = CryptographyPlaceholder


    class HashesPlaceholder:
        @staticmethod
        def SHA256():
            raise ImportError("Cryptography library not available")


    hashes = HashesPlaceholder()


class Config:
    """Application configuration constants"""

    # Email configuration for 2FA
    SMTP_EMAIL = "aplikovanakryptografie@gmail.com"
    SMTP_PASSWORD = "mgaw wcvw xtpv xoqb"
    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 587

    # Security settings
    PBKDF2_ITERATIONS = 100000
    VERIFICATION_CODE_LENGTH = 6
    CODE_EXPIRATION_MINUTES = 5
    SALT_LENGTH = 16

    # File paths
    USERS_FILE = "users.json"
    PASSWORDS_FILE = "passwords.json"
    LOG_FILE = "audit.log"
    CONFIG_FILE = "user_configs.json"

    # Encryption algorithms
    ALGORITHMS = {
        "AES-GCM": {"key_size": 32, "description": "AES-256 with Galois Counter Mode", "nonce_size": 12},
        "ChaCha20-Poly1305": {"key_size": 32, "description": "ChaCha20 stream cipher with Poly1305 MAC",
                              "nonce_size": 12},
        "Fernet": {"key_size": 32, "description": "Symmetric encryption using AES-128 in CBC mode"}
    }

    # Integrity methods
    INTEGRITY_METHODS = ["SHA256", "SHA512", "HMAC-SHA256"]


class FileHandler:
    """Handles file operations with proper error handling"""

    @staticmethod
    def write_text_file(file_path: str, content: str, encoding: str = 'utf-8'):
        """Write text content to file"""
        try:
            with open(file_path, 'w', encoding=encoding) as f:
                f.write(content)
        except OSError:
            pass

    @staticmethod
    def read_text_file(file_path: str, encoding: str = 'utf-8') -> str:
        """Read text content from file"""
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                return f.read()
        except OSError:
            return ""

    @staticmethod
    def append_text_file(file_path: str, content: str, encoding: str = 'utf-8'):
        """Append text content to file"""
        try:
            with open(file_path, 'a', encoding=encoding) as f:
                f.write(content)
        except OSError:
            pass

    @staticmethod
    def write_json_file(file_path: str, data: Dict[str, Any]):
        """Write JSON data to file"""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except OSError:
            pass

    @staticmethod
    def read_json_file(file_path: str) -> Dict[str, Any]:
        """Read JSON data from file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return {}


class SecurityLogger:
    """Handles security event logging"""

    def __init__(self):
        self.log_file = Config.LOG_FILE
        self._ensure_log_file()

    def _ensure_log_file(self):
        """Create log file if it doesn't exist"""
        if not os.path.exists(self.log_file):
            initial_content = f"[{datetime.now().isoformat()}] Security audit log initialized\n"
            FileHandler.write_text_file(self.log_file, initial_content)

    def log_event(self, event: str, username: str = "SYSTEM", level: str = "INFO"):
        """Log security event with timestamp"""
        timestamp = datetime.now().isoformat()
        log_entry = f"[{timestamp}] [{level}] [{username}] {event}\n"
        FileHandler.append_text_file(self.log_file, log_entry)

    def get_logs(self) -> str:
        """Retrieve all log entries"""
        logs = FileHandler.read_text_file(self.log_file)
        return logs if logs else "No logs available"


class CryptoManager:
    """Handles encryption and decryption operations"""

    @staticmethod
    def derive_key(password: str, salt: bytes, key_size: int = 32) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        if not CRYPTO_AVAILABLE:
            raise ImportError("Cryptography library not available")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_size,
            salt=salt,
            iterations=Config.PBKDF2_ITERATIONS,
        )
        return kdf.derive(password.encode())

    @staticmethod
    def encrypt_data(data: str, password: str, algorithm: str) -> Dict[str, str]:
        """Encrypt data using specified algorithm"""
        if not CRYPTO_AVAILABLE:
            raise ImportError("Cryptography library not available")

        salt = secrets.token_bytes(Config.SALT_LENGTH)
        key = CryptoManager.derive_key(password, salt, Config.ALGORITHMS[algorithm]["key_size"])
        nonce_size = Config.ALGORITHMS[algorithm].get("nonce_size")

        if algorithm in ["AES-GCM", "ChaCha20-Poly1305"] and nonce_size:
            cipher_class = {"AES-GCM": AESGCM, "ChaCha20-Poly1305": ChaCha20Poly1305}[algorithm]
            cipher = cipher_class(key)
            nonce = secrets.token_bytes(nonce_size)
            ciphertext = cipher.encrypt(nonce, data.encode(), None)
            encrypted_payload = nonce + ciphertext
        elif algorithm == "Fernet":
            fernet_cipher = Fernet(base64.urlsafe_b64encode(key))
            encrypted_payload = fernet_cipher.encrypt(data.encode())
        else:
            raise ValueError(f"Unsupported or misconfigured algorithm: {algorithm}")

        return {
            "algorithm": algorithm,
            "salt": base64.b64encode(salt).decode(),
            "data": base64.b64encode(encrypted_payload).decode()
        }

    @staticmethod
    def decrypt_data(encrypted_package: Dict[str, str], password: str) -> str:
        """Decrypt data using stored algorithm"""
        if not CRYPTO_AVAILABLE:
            raise ImportError("Cryptography library not available")

        algorithm = encrypted_package["algorithm"]
        salt = base64.b64decode(encrypted_package["salt"])
        encrypted_payload = base64.b64decode(encrypted_package["data"])
        key = CryptoManager.derive_key(password, salt, Config.ALGORITHMS[algorithm]["key_size"])
        nonce_size = Config.ALGORITHMS[algorithm].get("nonce_size")

        if algorithm in ["AES-GCM", "ChaCha20-Poly1305"] and nonce_size:
            cipher_class = {"AES-GCM": AESGCM, "ChaCha20-Poly1305": ChaCha20Poly1305}[algorithm]
            cipher = cipher_class(key)
            nonce = encrypted_payload[:nonce_size]
            ciphertext = encrypted_payload[nonce_size:]
            decrypted_data = cipher.decrypt(nonce, ciphertext, None)
        elif algorithm == "Fernet":
            fernet_cipher = Fernet(base64.urlsafe_b64encode(key))
            decrypted_data = fernet_cipher.decrypt(encrypted_payload)
        else:
            raise ValueError(f"Unsupported or misconfigured algorithm: {algorithm}")

        return decrypted_data.decode()

    @staticmethod
    def compute_integrity(data: bytes, method: str, key: Optional[bytes] = None) -> bytes:
        """Compute integrity hash"""
        if method == "SHA256":
            return hashlib.sha256(data).digest()
        if method == "SHA512":
            return hashlib.sha512(data).digest()
        if method == "HMAC-SHA256":
            if key is None:
                raise ValueError("HMAC requires a key")
            return hmac.new(key, data, hashlib.sha256).digest()
        raise ValueError(f"Unsupported integrity method: {method}")


class TwoFactorAuth:
    """Handles two-factor authentication via email"""

    def __init__(self, logger: SecurityLogger):
        self.logger = logger
        self.pending_codes: Dict[str, Dict[str, Any]] = {}

    @staticmethod
    def generate_code() -> str:
        """Generate secure verification code"""
        return ''.join(secrets.choice('0123456789') for _ in range(Config.VERIFICATION_CODE_LENGTH))

    def send_code(self, email: str, username: str) -> bool:
        """Send verification code via email"""
        code = self.generate_code()
        expiry = datetime.now() + timedelta(minutes=Config.CODE_EXPIRATION_MINUTES)

        try:
            msg = MIMEMultipart()
            msg['From'] = Config.SMTP_EMAIL
            msg['To'] = email
            msg['Subject'] = "Password Manager - Verification Code"
            body = f"Your verification code is: {code}\n\n" \
                   f"This code will expire in {Config.CODE_EXPIRATION_MINUTES} minutes.\n" \
                   f"If you did not request this code, please ignore this email."
            msg.attach(MIMEText(body, 'plain'))

            with smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT) as server:
                server.starttls()
                server.login(Config.SMTP_EMAIL, Config.SMTP_PASSWORD)
                server.send_message(msg)

            self.pending_codes[username] = {"code": code, "expiry": expiry}
            masked_email = f"{email[:3]}***@{email.split('@')[1]}" if '@' in email else "***"
            self.logger.log_event(f"2FA code sent to {masked_email}", username)
            return True

        except Exception as e:
            self.logger.log_event(f"Failed to send 2FA code: {str(e)}", username, "ERROR")
            return False

    def verify_code(self, username: str, submitted_code: str) -> bool:
        """Verify submitted code"""
        if username not in self.pending_codes:
            return False

        stored_data = self.pending_codes[username]

        if datetime.now() > stored_data["expiry"]:
            del self.pending_codes[username]
            return False

        if hmac.compare_digest(stored_data["code"], submitted_code):
            del self.pending_codes[username]
            self.logger.log_event("2FA verification successful", username)
            return True

        self.logger.log_event("2FA verification failed", username, "WARNING")
        return False


class UserManager:
    """Handles user registration and authentication"""

    def __init__(self, logger: SecurityLogger):
        self.logger = logger
        self.users_file = Config.USERS_FILE
        self._ensure_file()

    def _ensure_file(self):
        """Create users file if it doesn't exist"""
        if not os.path.exists(self.users_file):
            FileHandler.write_json_file(self.users_file, {})

    @staticmethod
    def load_users() -> Dict[str, Any]:
        """Load users from file"""
        return FileHandler.read_json_file(Config.USERS_FILE)

    @staticmethod
    def save_users(users: Dict[str, Any]):
        """Save users to file"""
        FileHandler.write_json_file(Config.USERS_FILE, users)

    @staticmethod
    def hash_password(password: str) -> Tuple[str, str]:
        """Hash password with salt"""
        salt = secrets.token_hex(16)
        password_hash = hashlib.pbkdf2_hmac(
            'sha256', password.encode(), salt.encode(), Config.PBKDF2_ITERATIONS
        )
        return salt, base64.b64encode(password_hash).decode()

    @staticmethod
    def verify_password(password: str, salt: str, stored_hash: str) -> bool:
        """Verify password against stored hash"""
        password_hash = hashlib.pbkdf2_hmac(
            'sha256', password.encode(), salt.encode(), Config.PBKDF2_ITERATIONS
        )
        return hmac.compare_digest(base64.b64decode(stored_hash), password_hash)

    def register_user(self, username: str, password: str, email: str) -> bool:
        """Register new user"""
        users = self.load_users()

        if username in users:
            return False

        salt, password_hash = self.hash_password(password)
        users[username] = {
            "salt": salt,
            "password_hash": password_hash,
            "email": email,
            "created": datetime.now().isoformat()
        }

        self.save_users(users)
        self.logger.log_event("User registered", username)
        return True

    def authenticate_user(self, username: str, password: str) -> Tuple[bool, str]:
        """Authenticate user and return success status and email"""
        users = self.load_users()

        if username not in users:
            self.logger.log_event("Login attempt with non-existent username", username, "WARNING")
            return False, ""

        user_data = users[username]
        if self.verify_password(password, user_data["salt"], user_data["password_hash"]):
            self.logger.log_event("Password authentication successful", username)
            return True, user_data["email"]

        self.logger.log_event("Password authentication failed", username, "WARNING")
        return False, ""


class PasswordVault:
    """Handles encrypted password storage"""

    def __init__(self, logger: SecurityLogger):
        self.logger = logger
        self.passwords_file = Config.PASSWORDS_FILE
        self.config_file = Config.CONFIG_FILE
        self._ensure_files()

    def _ensure_files(self):
        """Create necessary files if they don't exist"""
        for file_path in [self.passwords_file, self.config_file]:
            if not os.path.exists(file_path):
                FileHandler.write_json_file(file_path, {})

    def get_user_config(self, username: str) -> Dict[str, str]:
        """Get user's encryption configuration"""
        configs = FileHandler.read_json_file(self.config_file)
        return configs.get(username, {
            "algorithm": "AES-GCM",
            "integrity_method": "HMAC-SHA256"
        })

    def set_user_config(self, username: str, algorithm: str, integrity_method: str):
        """Set user's encryption configuration"""
        configs = FileHandler.read_json_file(self.config_file)
        configs[username] = {
            "algorithm": algorithm,
            "integrity_method": integrity_method,
            "updated": datetime.now().isoformat()
        }
        FileHandler.write_json_file(self.config_file, configs)
        self.logger.log_event(f"Encryption config updated: {algorithm}, {integrity_method}", username)

    def load_passwords(self, username: str, master_password: str) -> Dict[str, Any]:
        """Load and decrypt user's passwords"""
        if not CRYPTO_AVAILABLE:
            raise ImportError("Cryptography library not available")

        all_data = FileHandler.read_json_file(self.passwords_file)
        if username not in all_data:
            return {}

        user_data = all_data[username]
        try:
            if "integrity" in user_data:
                self._verify_integrity(user_data, master_password)

            encrypted_passwords = user_data["encrypted_passwords"]
            decrypted_json = CryptoManager.decrypt_data(encrypted_passwords, master_password)
            passwords = json.loads(decrypted_json)

            self.logger.log_event("Password vault accessed", username)
            return passwords
        except Exception as e:
            self.logger.log_event(f"Failed to load passwords: {str(e)}", username, "ERROR")
            raise ValueError("Failed to decrypt passwords. Check master password or data integrity.")

    def save_passwords(self, username: str, passwords: Dict[str, Any], master_password: str) -> bool:
        """Encrypt and save user's passwords"""
        if not CRYPTO_AVAILABLE:
            return False
        try:
            config = self.get_user_config(username)
            passwords_json = json.dumps(passwords, indent=2)
            encrypted_package = CryptoManager.encrypt_data(
                passwords_json, master_password, config["algorithm"]
            )

            integrity_data = self._compute_integrity_package(
                encrypted_package, master_password, config["integrity_method"]
            )

            user_data = {
                "encrypted_passwords": encrypted_package,
                "integrity": integrity_data,
                "last_updated": datetime.now().isoformat()
            }

            all_data = FileHandler.read_json_file(self.passwords_file)
            all_data[username] = user_data
            FileHandler.write_json_file(self.passwords_file, all_data)

            self.logger.log_event("Password vault updated", username)
            return True
        except Exception as e:
            self.logger.log_event(f"Failed to save passwords: {str(e)}", username, "ERROR")
            return False

    @staticmethod
    def _compute_integrity_package(encrypted_package: Dict[str, str], master_password: str,
                                   method: str) -> Dict[str, str]:
        """Compute integrity hash for encrypted data"""
        data_to_hash = json.dumps(encrypted_package, sort_keys=True).encode()
        key = None
        if method == "HMAC-SHA256":
            salt = base64.b64decode(encrypted_package["salt"])
            key = CryptoManager.derive_key(master_password, salt)

        integrity_hash = CryptoManager.compute_integrity(data_to_hash, method, key)
        return {"method": method, "hash": base64.b64encode(integrity_hash).decode()}

    def _verify_integrity(self, user_data: Dict[str, Any], master_password: str):
        """Verify integrity of encrypted data"""
        stored_integrity = user_data["integrity"]
        encrypted_package = user_data["encrypted_passwords"]
        computed_integrity = self._compute_integrity_package(
            encrypted_package, master_password, stored_integrity["method"]
        )
        if not hmac.compare_digest(stored_integrity["hash"], computed_integrity["hash"]):
            raise ValueError("Integrity verification failed - data may have been tampered with")

    def _atomic_update(self, username: str, master_password: str,
                       update_action: Callable[[Dict[str, Any]], Dict[str, Any]]) -> bool:
        """Atomically load, modify, and save the password vault."""
        try:
            passwords = self.load_passwords(username, master_password)
            updated_passwords = update_action(passwords)
            return self.save_passwords(username, updated_passwords, master_password)
        except ValueError as e:
            # Re-raise to be caught by the GUI
            raise e
        except Exception as e:
            self.logger.log_event(f"Atomic update failed: {e}", username, "ERROR")
            return False

    def add_password(self, username: str, service: str, service_username: str,
                     service_password: str, master_password: str) -> bool:
        """Add new password entry"""

        def add_action(passwords: Dict[str, Any]) -> Dict[str, Any]:
            passwords[service] = {
                "username": service_username,
                "password": service_password,
                "created": datetime.now().isoformat(),
                "updated": datetime.now().isoformat()
            }
            return passwords

        if self._atomic_update(username, master_password, add_action):
            self.logger.log_event(f"Password added for service: {service}", username)
            return True
        return False

    def update_password(self, username: str, service: str, service_username: str,
                        service_password: str, master_password: str) -> bool:
        """Update existing password entry"""

        def update_action(passwords: Dict[str, Any]) -> Dict[str, Any]:
            if service in passwords:
                passwords[service].update({
                    "username": service_username,
                    "password": service_password,
                    "updated": datetime.now().isoformat()
                })
            return passwords

        if self._atomic_update(username, master_password, update_action):
            self.logger.log_event(f"Password updated for service: {service}", username)
            return True
        return False

    def delete_password(self, username: str, service: str, master_password: str) -> bool:
        """Delete password entry"""

        def delete_action(passwords: Dict[str, Any]) -> Dict[str, Any]:
            if service in passwords:
                del passwords[service]
            return passwords

        if self._atomic_update(username, master_password, delete_action):
            self.logger.log_event(f"Password deleted for service: {service}", username)
            return True
        return False


class GUIHelpers:
    """Helper methods for GUI operations"""

    @staticmethod
    def create_labeled_entry(parent, label_text: str, row: int, width: int = 30, show: str = "") -> ttk.Entry:
        """Create labeled entry widget with consistent formatting"""
        ttk.Label(parent, text=label_text).grid(row=row, column=0, sticky=tk.W, pady=5, padx=5)
        entry = ttk.Entry(parent, width=width, show=show)
        entry.grid(row=row, column=1, pady=5, padx=(10, 5), sticky=tk.EW)
        return entry

    @staticmethod
    def create_button_frame(parent, buttons_config: list) -> ttk.Frame:
        """Create frame with multiple buttons"""
        button_frame = ttk.Frame(parent)
        for i, (text, command) in enumerate(buttons_config):
            ttk.Button(button_frame, text=text, command=command).pack(side=tk.LEFT, padx=5)
        return button_frame

    @staticmethod
    def setup_treeview_with_scrollbar(parent, columns: Tuple[str, ...], height: int = 15):
        """Setup treeview with scrollbar"""
        tree = ttk.Treeview(parent, columns=columns, show="headings", height=height)
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=150)
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        return tree, scrollbar

    @staticmethod
    def center_window(window: tk.Toplevel or tk.Tk):
        """Center a window on the screen."""
        window.update_idletasks()
        width = window.winfo_width()
        height = window.winfo_height()
        x = (window.winfo_screenwidth() // 2) - (width // 2)
        y = (window.winfo_screenheight() // 2) - (height // 2)
        window.geometry(f"{width}x{height}+{x}+{y}")


class PasswordManagerGUI:
    """Main GUI application"""

    def __init__(self):
        self.logger = SecurityLogger()
        self.user_manager = UserManager(self.logger)
        self.two_factor = TwoFactorAuth(self.logger)
        self.vault = PasswordVault(self.logger)

        self.current_user = None
        self.master_password = None

        self.root = tk.Tk()
        # Initialize GUI attributes to None
        self.username_entry = self.password_entry = self.email_entry = self.status_label = None
        self.service_entry = self.service_username_entry = self.service_password_entry = None
        self.password_tree = self.algorithm_var = self.integrity_var = self.log_text = None
        self.show_password_var = None

        self.setup_gui()
        self.logger.log_event("Application started")

    def setup_gui(self):
        """Setup main GUI window"""
        self.root.title("2FA Password Manager")
        self.root.geometry("400x350")
        self.create_login_interface()

    def create_login_interface(self):
        """Create login/registration interface"""
        for widget in self.root.winfo_children():
            widget.destroy()

        self.root.geometry("400x350")
        GUIHelpers.center_window(self.root)

        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.grid_columnconfigure(1, weight=1)

        title_label = ttk.Label(main_frame, text="Password Manager", font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))

        self.username_entry = GUIHelpers.create_labeled_entry(main_frame, "Username:", 1)
        self.password_entry = GUIHelpers.create_labeled_entry(main_frame, "Password:", 2, show="*")
        self.email_entry = GUIHelpers.create_labeled_entry(main_frame, "Email (registration):", 3)

        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=2, pady=20)
        ttk.Button(button_frame, text="Login", command=self.login).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Register", command=self.register).pack(side=tk.LEFT)

        self.status_label = ttk.Label(main_frame, text="", foreground="red", anchor="center")
        self.status_label.grid(row=5, column=0, columnspan=2, pady=(10, 0), sticky="ew")

        self.root.bind('<Return>', self.on_enter_key)
        self.username_entry.focus()

    def on_enter_key(self, _event):
        """Handle Enter key press on login screen."""
        focused_widget = self.root.focus_get()
        if focused_widget in (self.username_entry, self.password_entry, self.email_entry):
            self.login()

    def show_status(self, message: str, color: str = "red"):
        """Show status message"""
        if self.status_label:
            self.status_label.config(text=message, foreground=color)
            self.root.after(5000, self.clear_status)

    def clear_status(self):
        """Clear status message"""
        if self.status_label:
            self.status_label.config(text="")

    def register(self):
        """Handle user registration"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        email = self.email_entry.get().strip()

        if not all([username, password, email]):
            self.show_status("Please fill in all fields")
            return
        if len(password) < 8:
            self.show_status("Password must be at least 8 characters")
            return
        if "@" not in email:
            self.show_status("Please enter a valid email address")
            return

        if self.user_manager.register_user(username, password, email):
            self.show_status("Registration successful! You can now login.", "green")
            self.clear_fields()
        else:
            self.show_status("Username already exists")

    def login(self):
        """Handle user login"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            self.show_status("Please enter username and password")
            return

        success, email = self.user_manager.authenticate_user(username, password)

        if success and email:
            if self.two_factor.send_code(email, username):
                self.show_2fa_dialog(username, password)
            else:
                self.show_status("Failed to send verification code")
        elif success and not email:
            self.show_status("No email found for 2FA")
        else:
            self.show_status("Invalid credentials")

    def show_2fa_dialog(self, username: str, password: str):
        """Show 2FA verification dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Two-Factor Authentication")
        dialog.geometry("300x200")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        GUIHelpers.center_window(dialog)

        dialog_frame = ttk.Frame(dialog, padding="20")
        dialog_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(dialog_frame, text="Enter verification code sent to your email:",
                  wraplength=250).pack(pady=(0, 20))

        code_entry = ttk.Entry(dialog_frame, width=20, justify=tk.CENTER, font=("Arial", 12))
        code_entry.pack(pady=(0, 20))
        code_entry.focus()

        dialog_status_label = ttk.Label(dialog_frame, text="", foreground="red")
        dialog_status_label.pack(pady=(10, 0))

        def verify():
            code = code_entry.get().strip()
            if self.two_factor.verify_code(username, code):
                dialog.destroy()
                self.current_user = username
                self.master_password = password
                self.create_main_interface()
            else:
                dialog_status_label.config(text="Invalid or expired code")

        ttk.Button(dialog_frame, text="Verify", command=verify).pack()
        dialog.bind('<Return>', lambda e: verify())

    def clear_fields(self):
        """Clear all input fields"""
        if self.username_entry: self.username_entry.delete(0, tk.END)
        if self.password_entry: self.password_entry.delete(0, tk.END)
        if self.email_entry: self.email_entry.delete(0, tk.END)

    def create_main_interface(self):
        """Create main password management interface"""
        for widget in self.root.winfo_children():
            widget.destroy()

        self.root.geometry("800x600")
        GUIHelpers.center_window(self.root)

        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        password_frame = ttk.Frame(notebook)
        notebook.add(password_frame, text="Passwords")
        self.create_password_tab(password_frame)

        settings_frame = ttk.Frame(notebook)
        notebook.add(settings_frame, text="Settings")
        self.create_settings_tab(settings_frame)

        logs_frame = ttk.Frame(notebook)
        notebook.add(logs_frame, text="Audit Logs")
        self.create_logs_tab(logs_frame)

        self.create_menu_bar()

    def create_menu_bar(self):
        """Create application menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Logout", command=self.logout)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

    def create_password_tab(self, parent):
        """Create password management tab"""
        form_frame = ttk.LabelFrame(parent, text="Password Entry", padding="15")
        form_frame.pack(fill=tk.X, padx=10, pady=10)
        form_frame.grid_columnconfigure(1, weight=1)

        self.service_entry = GUIHelpers.create_labeled_entry(form_frame, "Service:", 0, width=35)
        self.service_username_entry = GUIHelpers.create_labeled_entry(form_frame, "Username:", 1, width=35)

        ttk.Label(form_frame, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=5, padx=5)
        password_container = ttk.Frame(form_frame)
        password_container.grid(row=2, column=1, pady=5, padx=(10, 5), sticky=tk.EW)
        password_container.grid_columnconfigure(0, weight=1)

        self.service_password_entry = ttk.Entry(password_container, show="*", width=30)
        self.service_password_entry.grid(row=0, column=0, sticky=tk.EW, padx=(0, 10))

        self.show_password_var = tk.BooleanVar()
        show_password_check = ttk.Checkbutton(
            password_container, text="Show", variable=self.show_password_var, command=self.toggle_password_visibility
        )
        show_password_check.grid(row=0, column=1, sticky=tk.W)

        buttons_config = [
            ("Add", self.add_password_entry), ("Update", self.update_password_entry),
            ("Delete", self.delete_password_entry), ("Clear", self.clear_password_form)
        ]
        button_frame = GUIHelpers.create_button_frame(form_frame, buttons_config)
        button_frame.grid(row=3, column=0, columnspan=2, pady=15)

        list_frame = ttk.LabelFrame(parent, text="Stored Passwords", padding="10")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        columns = ("Service", "Username", "Created", "Updated")
        self.password_tree, scrollbar = GUIHelpers.setup_treeview_with_scrollbar(list_frame, columns)
        self.password_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.password_tree.bind("<<TreeviewSelect>>", self.on_password_select)

        ttk.Button(list_frame, text="Refresh", command=self.refresh_password_list).pack(pady=10)
        self.refresh_password_list()

    def toggle_password_visibility(self):
        """Toggle password field visibility"""
        self.service_password_entry.config(show="" if self.show_password_var.get() else "*")

    def create_settings_tab(self, parent):
        """Create settings tab"""
        settings_frame = ttk.LabelFrame(parent, text="Encryption Settings", padding="20")
        settings_frame.pack(fill=tk.X, padx=10, pady=10)

        current_config = self.vault.get_user_config(self.current_user)
        self.algorithm_var = tk.StringVar(value=current_config["algorithm"])
        self.integrity_var = tk.StringVar(value=current_config["integrity_method"])

        ttk.Label(settings_frame, text="Encryption Algorithm:").grid(row=0, column=0, sticky=tk.W, pady=10)
        algorithm_combo = ttk.Combobox(settings_frame, textvariable=self.algorithm_var,
                                       values=list(Config.ALGORITHMS.keys()), state="readonly", width=25)
        algorithm_combo.grid(row=0, column=1, pady=10, padx=(10, 0))

        ttk.Label(settings_frame, text="Integrity Method:").grid(row=1, column=0, sticky=tk.W, pady=10)
        integrity_combo = ttk.Combobox(settings_frame, textvariable=self.integrity_var,
                                       values=Config.INTEGRITY_METHODS, state="readonly", width=25)
        integrity_combo.grid(row=1, column=1, pady=10, padx=(10, 0))

        ttk.Button(settings_frame, text="Save Settings",
                   command=self.save_settings).grid(row=2, column=0, columnspan=2, pady=20)

    def create_logs_tab(self, parent):
        """Create audit logs tab"""
        log_frame = ttk.LabelFrame(parent, text="Security Audit Log", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.log_text = tk.Text(log_frame, wrap=tk.NONE, font=("Courier", 10),
                                bg="black", fg="green", state=tk.DISABLED)
        v_scroll = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        h_scroll = ttk.Scrollbar(log_frame, orient=tk.HORIZONTAL, command=self.log_text.xview)
        self.log_text.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        self.log_text.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")
        log_frame.grid_rowconfigure(0, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)

        ttk.Button(log_frame, text="Refresh Logs", command=self.refresh_logs).grid(row=2, column=0, pady=10)
        self.refresh_logs()

    def refresh_logs(self):
        """Refresh audit log display"""
        if self.log_text:
            self.log_text.config(state=tk.NORMAL)
            self.log_text.delete(1.0, tk.END)
            self.log_text.insert(tk.END, self.logger.get_logs())
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)

    def save_settings(self):
        """Save encryption settings"""
        self.vault.set_user_config(
            self.current_user, self.algorithm_var.get(), self.integrity_var.get()
        )
        messagebox.showinfo("Settings", "Settings saved successfully!")

    def _execute_vault_operation(self, operation: Callable, success_msg: str, *op_args,
                                 confirm: bool = False, confirm_msg: str = ""):
        """Helper to execute vault operations, handling confirmation and errors."""
        if confirm and not messagebox.askyesno("Confirm", confirm_msg):
            return
        try:
            if operation(*op_args):
                messagebox.showinfo("Success", success_msg)
                self.clear_password_form()
                self.refresh_password_list()
            else:
                messagebox.showerror("Error", f"Failed to {operation.__name__.replace('_', ' ')}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _get_password_form_data(self) -> Optional[Tuple[str, str, str]]:
        """Gets and validates data from the password entry form."""
        if not self.validate_password_form():
            return None
        service = self.service_entry.get().strip()
        username = self.service_username_entry.get().strip()
        password = self.service_password_entry.get().strip()
        return service, username, password

    def add_password_entry(self):
        """Add new password entry"""
        form_data = self._get_password_form_data()
        if form_data is None:
            return
        service, username, password = form_data
        # FIX: Corrected argument order
        self._execute_vault_operation(
            self.vault.add_password,
            "Password added successfully!",
            self.current_user, service, username, password, self.master_password
        )

    def update_password_entry(self):
        """Update existing password entry"""
        form_data = self._get_password_form_data()
        if form_data is None:
            return
        service, username, password = form_data
        # FIX: Corrected argument order
        self._execute_vault_operation(
            self.vault.update_password,
            "Password updated successfully!",
            self.current_user, service, username, password, self.master_password
        )

    def delete_password_entry(self):
        """Delete password entry"""
        service = self.service_entry.get().strip()
        if not service:
            messagebox.showerror("Error", "Please select a service to delete")
            return
        # FIX: Corrected argument order
        self._execute_vault_operation(
            self.vault.delete_password,
            "Password deleted successfully!",
            self.current_user, service, self.master_password,
            confirm=True, confirm_msg=f"Delete password for '{service}'?"
        )

    def validate_password_form(self) -> bool:
        """Validate password form fields"""
        if not all(e.get().strip() for e in
                   [self.service_entry, self.service_username_entry, self.service_password_entry]):
            messagebox.showerror("Error", "Please fill in all fields")
            return False
        return True

    def clear_password_form(self):
        """Clear password form fields and selection."""
        for entry in [self.service_entry, self.service_username_entry, self.service_password_entry]:
            if entry:
                entry.delete(0, tk.END)
        if self.password_tree and self.password_tree.selection():
            self.password_tree.selection_remove(self.password_tree.selection())

    def refresh_password_list(self):
        """Refresh password list display"""
        if not self.password_tree: return
        for item in self.password_tree.get_children():
            self.password_tree.delete(item)
        try:
            passwords = self.vault.load_passwords(self.current_user, self.master_password)
            for service, data in sorted(passwords.items()):
                self.password_tree.insert("", tk.END, values=(
                    service, data["username"],
                    data.get("created", "N/A")[:16], data.get("updated", "N/A")[:16]
                ))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load passwords: {e}")
            self.logout()  # Logout on fatal password load error

    def on_password_select(self, _event):
        """Handle password selection in tree"""
        if not self.password_tree.selection(): return
        item = self.password_tree.item(self.password_tree.selection()[0])
        service = item["values"][0]
        try:
            passwords = self.vault.load_passwords(self.current_user, self.master_password)
            if service in passwords:
                data = passwords[service]
                self.clear_password_form()
                self.service_entry.insert(0, service)
                self.service_username_entry.insert(0, data["username"])
                self.service_password_entry.insert(0, data["password"])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load password details: {e}")

    def logout(self):
        """Logout current user"""
        if self.current_user:
            self.logger.log_event("User logged out", self.current_user)
        self.current_user = None
        self.master_password = None
        self.create_login_interface()

    def run(self):
        """Run the application"""
        try:
            self.root.mainloop()
        finally:
            self.logger.log_event("Application stopped", self.current_user or "SYSTEM")


def main():
    """Main application entry point"""
    if not CRYPTO_AVAILABLE:
        return
    try:
        app = PasswordManagerGUI()
        app.run()
    except Exception as e:
        print(f"Critical error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()