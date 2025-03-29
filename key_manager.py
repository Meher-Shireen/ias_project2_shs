# key_manager.py
import os

def get_aes_key():
    key_path = "aes_key.bin"
    if not os.path.exists(key_path):
        # Generate new key if missing
        key = os.urandom(32)
        with open(key_path, "wb") as f:
            f.write(key)
        os.chmod(key_path, 0o600)  # Restrict permissions
        return key
    with open(key_path, "rb") as f:
        return f.read()