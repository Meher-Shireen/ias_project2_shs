import requests

url = "http://127.0.0.1:5000/register_device"
data = {
    "device_name": "Smart_Lock",
    "user_id": 6
}

response = requests.post(url, json=data)
print(response.json())
#print(f"Status Code: {response.status_code}")
#print(f"Response Text: {response.text}")  # Print raw response
