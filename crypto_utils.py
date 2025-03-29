
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64
import os

# AES Key for encryption (must be stored securely)
#AES_KEY = os.urandom(32)  # 256-bit AES key

import rsa
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import sympy
import random

# === Vedic Multiplication ===
def vedic_multiply(x, y):
    """ Urdhva Tiryakbhayam (Vertical and Crosswise) multiplication """
    x, y = str(x), str(y)
    len_x, len_y = len(x), len(y)

    if len_x == 1 or len_y == 1:  
        return int(x) * int(y)

    half_len = max(len_x, len_y) // 2
    xL, xR = int(x[:-half_len]), int(x[-half_len:])
    yL, yR = int(y[:-half_len]), int(y[-half_len:])

    # Recursively calculate
    P1 = vedic_multiply(xL, yL)
    P2 = vedic_multiply(xR, yR)
    P3 = vedic_multiply(xL + xR, yL + yR) - P1 - P2

    return P1 * (10 ** (2 * half_len)) + P3 * (10 ** half_len) + P2

# === Vedic Modular Exponentiation ===
def vedic_mod_exp(base, exp, mod):
    """ Uses Vedic multiplication for modular exponentiation """
    result = 1
    base = base % mod

    while exp > 0:
        if exp % 2 == 1:  # If exponent is odd
            result = vedic_multiply(result, base) % mod
        exp = exp >> 1  # Divide exponent by 2
        base = vedic_multiply(base, base) % mod

    return result

# === RSA Key Generation with Vedic Maths ===
def generate_rsa_keypair():
    """Generates RSA key pair using Vedic Math and returns PEM-encoded keys."""

    # Generate large prime numbers using sympy
    p = sympy.randprime(10**4, 10**5)
    q = sympy.randprime(10**4, 10**5)

    # Compute modulus n
    n = vedic_multiply(p, q)  # Optimized multiplication

    # Compute Euler’s Totient Function
    phi_n = vedic_multiply(p - 1, q - 1)

    # Choose a public exponent e (commonly 65537)
    e = 65537

    # Compute private exponent d using modular inverse
    d = pow(e, -1, phi_n)  # This uses Python’s built-in modular inverse

    # Generate RSA private and public key objects
    private_key = rsa.generate_private_key(
        public_exponent=e,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Convert keys to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return private_pem, public_pem

# === Test the RSA Key Generation ===
private_key, public_key = generate_rsa_keypair()
print("🔐 Private Key:\n", private_key)
print("🗝️ Public Key:\n", public_key)


AES_KEY_FILE = "aes_key.bin"
with open(AES_KEY_FILE, "rb") as key_file:
    AES_KEY = key_file.read()  # Read 32-byte AES key

def encrypt_private_key(private_key):
    """Encrypts the private key using AES-CBC with PKCS7 padding."""
    iv = os.urandom(16)  # Generate a random IV for each encryption
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Apply PKCS7 padding
    padder = padding.PKCS7(128).padder()
    padded_private_key = padder.update(private_key.encode()) + padder.finalize()

    encrypted_key = encryptor.update(padded_private_key) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_key).decode()  # Store IV + encrypted data

def decrypt_private_key(encrypted_key):
    """Decrypts the AES-encrypted private key using PKCS7 unpadding."""
    encrypted_key = base64.b64decode(encrypted_key)
    iv = encrypted_key[:16]  # Extract IV
    encrypted_data = encrypted_key[16:]  # Extract encrypted data

    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_key = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_key = unpadder.update(decrypted_padded_key) + unpadder.finalize()

    return decrypted_key.decode()