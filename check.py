import sqlite3

conn = sqlite3.connect("authentication.db")
cursor = conn.cursor()

cursor.execute("SELECT * FROM sqlite_sequence;")
data = cursor.fetchall()

print("Contents of sqlite_sequence:")
for row in data:
    print(row)

conn.close()
