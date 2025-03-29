import os
import base64
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def generate_biometric():
    """Generates a synthetic biometric hash using PBKDF2-HMAC-SHA256."""
    biometric_seed = os.urandom(32)  # 32-byte random seed (acts as biometric)
    salt = os.urandom(16)  # Random salt for PBKDF2
    biometric_hash = hashlib.pbkdf2_hmac('sha256', biometric_seed, salt, 100000)
    return base64.b64encode(biometric_hash).decode()

# ============================
# AES Encryption (Symmetric)
# ============================

def encrypt_aes(data: str, key: bytes) -> str:
    """Encrypts data using AES-CBC and returns base64-encoded ciphertext."""
    
    iv = os.urandom(16)  # Generate IV
    
    print(f"[Encryption] IV: {iv.hex()}")  # Debugging
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Apply PKCS7 padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()

    # Encrypt and prepend IV
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

def decrypt_aes(enc_data: str, key: bytes) -> str:
    """Decrypts base64-encoded AES-CBC ciphertext."""
    
    try:
        enc_data = base64.b64decode(enc_data)
        iv, ciphertext = enc_data[:16], enc_data[16:]
        
        print(f"[Decryption] IV: {iv.hex()}")  # Debugging

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove PKCS7 padding
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(padded_data) + unpadder.finalize()

        return decrypted_data.decode()

    except (ValueError, base64.binascii.Error) as e:
        print(f"[Error] Decryption failed: {str(e)}")
        return None


# ==============================
# RSA Encryption (Asymmetric)
# ==============================
def generate_rsa_keys():
    """Generates RSA private and public key pair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_rsa(data: str, public_key):
    """Encrypts data using RSA public key."""
    encrypted = public_key.encrypt(
        data.encode(),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()
    
def decrypt_rsa(encrypted_data: str, private_key):
    """Decrypts RSA encrypted data using private key."""
    encrypted_data = base64.b64decode(encrypted_data)
    decrypted = private_key.decrypt(
        encrypted_data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

# ==============================
# HMAC-SHA256 (Data Integrity)
# ==============================
def generate_hmac(message: str, key: bytes) -> str:
    """Generates HMAC-SHA256 signature for data integrity."""
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()

def verify_hmac(message: str, key: bytes, received_hmac: str) -> bool:
    """Verifies HMAC signature."""
    return hmac.compare_digest(generate_hmac(message, key), received_hmac)

# ==============================
# SHA-256 Hashing (Password Storage)
# ==============================
def hash_password(password: str) -> tuple:
    """Hashes password using SHA-256 with a salt."""
    salt = os.urandom(16)
    hashed_pw = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return hashed_pw, salt

def verify_password(password: str, stored_hash: bytes, salt: bytes) -> bool:
    """Verifies if entered password matches stored hash."""
    new_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return new_hash == stored_hash

# ==============================
# Example Usage
# ==============================
if __name__ == "__main__":
    # AES Encryption Test
    #aes_key = os.urandom(32)  # 256-bit key
    aes_key = bytes.fromhex('89f3128ecf7b94aa1d7fe3169a21bb5c4502d98173c4af37620e8fd5aa12bedc')
  # 256-bit key
    encrypted_msg = encrypt_aes("Hello, Secure World!", aes_key)
    decrypted_msg = decrypt_aes(encrypted_msg, aes_key)
    print("AES Encrypted:", encrypted_msg)
    print("AES Decrypted:", decrypted_msg)

    # RSA Encryption Test
    private_key, public_key = generate_rsa_keys()
    encrypted_rsa_msg = encrypt_rsa("Secure RSA Message", public_key)
    decrypted_rsa_msg = decrypt_rsa(encrypted_rsa_msg, private_key)
    print("RSA Encrypted:", encrypted_rsa_msg)
    print("RSA Decrypted:", decrypted_rsa_msg)

    # HMAC Integrity Test
    hmac_key = os.urandom(32)
    message = "Verify this data"
    hmac_value = generate_hmac(message, hmac_key)
    print("HMAC:", hmac_value)
    print("HMAC Verified:", verify_hmac(message, hmac_key, hmac_value))

    # Password Hashing Test
    password = "SuperSecurePassword"
    hashed_pw, salt = hash_password(password)
    print("Password Hash Verified:", verify_password(password, hashed_pw, salt))
