import requests

url = "http://127.0.0.1:5000/register"
data = {
    "name": "Ahmad",
    "phone": "0700123456",
    "password": "12345",
    "role": "saraf"
}

response = requests.post(url, json=data)
print(response.json())