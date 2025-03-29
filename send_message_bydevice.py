import requests
from authentication import encrypt_aes
from key_manager import get_aes_key
# Define the API endpoint
url = "http://127.0.0.1:5000/send_message"

# Define the AES key (must match the key used in app.py)
#AES_KEY = b'\x89\xf3\x12\x8e\xcf\x7b\x94\xaa\x1d\x7f\xe3\x16\x9a\x21\xbb\x5c\x45\x02\xd9\x81\x73\xc4\xaf\x37\x62\x0e\x8f\xd5\xaa\x12\xbe\xdc'
AES_KEY = get_aes_key()
 # Replace with your actual 32-byte key

# Define the message to be encrypted
plaintext_message = "hellooo there"

# Encrypt the message
encrypted_message = encrypt_aes(plaintext_message, AES_KEY)

print(f"AES Key: {AES_KEY.hex()}")
print(f"Encrypted: {encrypted_message}")

# Define the message data
data = {
    "device_id": 1,
    "user_id": 1,
    "encrypted_message": encrypted_message  # Use the encrypted message
}

# Send the POST request
response = requests.post(url, json=data)

# Print the response
print(response.status_code)
print(response.json())