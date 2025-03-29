import sqlite3

conn = sqlite3.connect("authentication.db")
cursor = conn.cursor()

# # Delete all records from devices table (if you have one)
# cursor.execute("DELETE FROM devices")
# conn.commit()
# conn.close()

# print("All devices deleted from database.")

# from openpyxl import load_workbook

# wb = load_workbook("devices.xlsx")
# ws = wb.active

# # Keep headers, delete all data rows
# ws.delete_rows(2, ws.max_row)
# wb.save("devices.xlsx")

# print("All user records removed from Excel.")

# conn = sqlite3.connect("authentication.db")
# cursor = conn.cursor()

cursor.execute("DELETE FROM sqlite_sequence WHERE name='device_messages'")
conn.commit()
conn.close()
