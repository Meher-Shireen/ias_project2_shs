import requests

url = "http://127.0.0.1:5000/register"
data = {
    "username": "mmmeeehhhh",
    "password": "iotuopiu"
    #"biometric": "dc97kkld"
}

response = requests.post(url, json=data)
print(response.json())
