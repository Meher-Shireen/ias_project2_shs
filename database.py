import sqlite3

def init_db():
    conn = sqlite3.connect("authentication.db")
    cursor = conn.cursor()

    # Enable Foreign Key support (SQLite needs this explicitly)
    cursor.execute("PRAGMA foreign_keys = ON;")
    
    # User Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            biometric TEXT NOT NULL
        )
    ''')

    # Gateway Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS gateway (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            secret_key TEXT NOT NULL
        )
    ''')

    # Smart Devices Table (Linked to Users)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_name TEXT UNIQUE NOT NULL,
            secret TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # Messages Table (Linked to Devices and Users)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            encrypted_message TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_messages (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            encrypted_message TEXT NOT NULL,
            timestamp DATETIME NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    # Try adding extra columns to devices
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN user_public_key TEXT")
    except sqlite3.OperationalError:
        print("Column 'user_public_key' already exists in users")

    try:
        cursor.execute("ALTER TABLE users ADD COLUMN encrypted_user_private_key TEXT")
    except sqlite3.OperationalError:
        print("Column 'encrypted_user_private_key' already exists in users") 

    try:
        cursor.execute("ALTER TABLE devices ADD COLUMN device_public_key TEXT")
    except sqlite3.OperationalError:
        print("Column 'device_public_key' already exists in devices")

    try:
        cursor.execute("ALTER TABLE devices ADD COLUMN encrypted_device_private_key TEXT")
    except sqlite3.OperationalError:
        print("Column 'encrypted_device_private_key' already exists in devices")    

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Database initialized successfully!")
