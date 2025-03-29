import sqlite3

conn = sqlite3.connect("authentication.db")
cursor = conn.cursor()

cursor.execute("SELECT * FROM device_messages;")  # Fetch all user records
messages = cursor.fetchall()

print("Registered Users:")
for message in messages:
    print(message)

conn.close()
