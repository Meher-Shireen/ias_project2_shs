from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import requests
from authentication import decrypt_aes, encrypt_aes, verify_password
import sqlite3
from key_manager import get_aes_key
import base64
import rsa
from cryptography.hazmat.primitives import padding
from datetime import datetime
import binascii  # Add this import at the top with other imports
import re        # Also ensure re is imported
from cryptography.hazmat.primitives import serialization  # Additional import for key handling

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Required for session management

# Flask-Login setup
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Dummy User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_id):
        self.id = user_id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# Base URL of the backend API (app.py)
API_BASE_URL = "http://127.0.0.1:5000"

# Secret key for AES decryption (must match the key used in app.py)
AES_KEY = get_aes_key()
print(len(AES_KEY))  # Should print 32
  # Replace with your actual key

# @app.route('/')
# @login_required
# def index():
#     """Homepage with links to register users and devices."""
#     return render_template('index.html')
#     #return render_template('first_page.html')
    
@app.route('/')
def landing():
    """Landing page that shows first_page.html"""
    return render_template('first_page.html')

@app.route('/home')
@login_required
def index():
    """Homepage with links to register users and devices."""
    return render_template('index.html')
    
@app.route('/login', methods=['GET', 'POST']) 
def login():
    """Handles login for any registered user with password verification and backend biometric check."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Fetch user data from DB
        conn = sqlite3.connect("authentication.db")
        cursor = conn.cursor()
        cursor.execute("SELECT id, password, biometric FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        if result:
            user_id, stored_password, encrypted_biometric = result
            stored_hash_hex, salt_hex = stored_password.split(":")
            stored_hash = bytes.fromhex(stored_hash_hex)
            salt = bytes.fromhex(salt_hex)

            # Verify password
            if verify_password(password, stored_hash, salt):
                try:
                    # Try decrypting biometric to ensure it's valid (backend-only check)
                    decrypted_biometric = decrypt_aes(encrypted_biometric, AES_KEY)
                    if decrypted_biometric:  # Optional check (can just print/log if needed)
                        user = User(user_id)
                        login_user(user)
                        print("Login successful. Current user:", current_user.get_id())  # Add this
                        #return redirect(url_for('index'))
                        return redirect(url_for('index'))
                except Exception as e:
                    return f"Biometric verification failed: {str(e)}", 401
            else:
                return "Incorrect password", 401
        else:
            return "User not found", 404

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """Handles user logout."""
    logout_user()
    return redirect(url_for('login'))


@app.route('/register_user', methods=['GET', 'POST'])
def register_user():
    """Handles user registration via backend API."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        response = requests.post(f"{API_BASE_URL}/register", json={
            "username": username,
            "password": password
        })

        if response.status_code == 201:
            user_id = response.json().get("user_id")
            return render_template("registration_success.html", user_id=user_id)
        else:
            return f"Error: {response.json().get('error')}", response.status_code

    return render_template('register_user.html')


@app.route('/register_device', methods=['GET', 'POST'])
def register_device():
    """Handles device registration via an HTML form."""
    if request.method == 'POST':
        device_name = request.form['device_name']
        user_id = request.form['user_id']

        # Send data to backend API
        response = requests.post(f"{API_BASE_URL}/register_device", json={
            "device_name": device_name,
            "user_id": user_id
        })

        if response.status_code == 201:
            return redirect(url_for('index'))
        else:
            return f"Error: {response.json().get('error')}", response.status_code

    return render_template('register_device.html')

@app.route('/view_message')
@login_required
def view_message():
    """Displays the latest message received by the logged-in user."""
    user_id = current_user.id # Get user_id dynamically if needed
    #user_id = 4
    # Fetch the latest message from the backend API
    response = requests.get(f"{API_BASE_URL}/receive_message?user_id={user_id}")
    print("Response Status Code:", response.status_code)
    print("Response Content:", response.text)

    if response.status_code == 200:
        message_data = response.json()
        
        # **Fix: Use `decrypted_message` instead of `encrypted_message`**
        decrypted_message = message_data.get('decrypted_message')

        if decrypted_message:
            return render_template('view_message.html', message=decrypted_message)
        else:
            return "Error: Decrypted message not found in response", 500
    else:
        return f"Error: {response.json().get('error')}", response.status_code
    

@app.route('/send_message', methods=['GET', 'POST'], endpoint='send_message_from_user')
def send_message_from_user():
    if request.method == 'POST':
        device_id = request.form['device_id']
        message = request.form['message']

        # Encrypt the message
        encrypted_message = encrypt_aes(message, AES_KEY)

        # Define the message data
        data = {
            "device_id": device_id,
            "user_id": current_user.id,  # Assuming you have a current_user object
            "encrypted_message": encrypted_message
        }

        # Send the POST request to the backend
        response = requests.post(f"{API_BASE_URL}/send_message_to_device", json=data)

        if response.status_code == 201:
            return redirect(url_for('index'))
        else:
            return f"Error: {response.json().get('error')}", response.status_code

    return render_template('send_message.html')


@app.route('/send_to_device', methods=['GET', 'POST'])
@login_required
def send_to_device():
    if request.method == 'GET':
        # GET handling - show form with devices dropdown
        conn = sqlite3.connect("authentication.db")
        cursor = conn.cursor()
        cursor.execute("SELECT id, device_name FROM devices WHERE user_id = ?", (current_user.id,))
        devices = cursor.fetchall()
        conn.close()
        return render_template('send_to_device.html', devices=devices)

    # POST handling - process form submission
    try:
        print("\n=== Form Submission ===")
        print("Form data:", request.form)
        
        device_id = request.form['device_id']
        message = request.form['message']
        user_id = current_user.id
        
        print(f"Sending to device {device_id} (user {user_id}): {message}")

        # Send to backend API
        response = requests.post(
            f"{API_BASE_URL}/send_message_to_device",
            json={
                "device_id": device_id,
                "message": message,
                "user_id": user_id
            },
            headers={'Content-Type': 'application/json'},
            timeout=5
        )
        
        print("Backend response:", response.status_code, response.text)

        # Handle response
        if response.status_code == 200:
            return render_template('message_status.html',
                                success=True,
                                device_id=device_id,
                                message=message,
                                response=response.json())
        
        # Handle error responses
        try:
            error_data = response.json()
            return render_template('message_status.html',
                                error=error_data.get('error', 'Unknown error'),
                                status_code=response.status_code)
        except ValueError:
            return render_template('message_status.html',
                                error=response.text,
                                status_code=response.status_code)

    except requests.exceptions.RequestException as e:
        print(f"Request failed: {str(e)}")
        return render_template('message_status.html',
                            error=f"Connection error: {str(e)}",
                            status_code=500)
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return render_template('message_status.html',
                            error=f"System error: {str(e)}",
                            status_code=500)

@app.route('/device_messages/<int:device_id>')
def device_messages(device_id):
    """Endpoint for devices to fetch their messages (called by devices directly)."""
    secret = request.args.get("secret")
    if not secret:
        return jsonify({"error": "Secret required"}), 403

    response = requests.get(
        f"{API_BASE_URL}/get_messages_for_device/{device_id}?secret={secret}"
    )
    return jsonify(response.json())

if __name__ == '__main__':
    app.run(debug=True, port=5001)