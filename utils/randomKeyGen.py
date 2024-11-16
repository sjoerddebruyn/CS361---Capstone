import json
import socket
import os
import hashlib
import hmac
import secrets
from pymongo import MongoClient
from dotenv import load_dotenv

# Load environment variables from the .env file
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB_NAME = MONGO_URI.split("/")[-1].split("?")[0]

try:
    client = MongoClient(MONGO_URI)
    db = client[MONGO_DB_NAME]
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")
    exit()

def salt_gen(length=16):
    return os.urandom(length)
    
def seed_gen():
    return secrets.token_hex(16)

def key_gen(salt, seed, length=32):
    return hmac.new(salt, seed.encode(), hashlib.sha256).digest()[:length]

def gen_encryption_comps():
    salt = salt_gen()
    seed = seed_gen()
    key = key_gen(salt, seed)
    return {
        'Salt': salt.hex(),
        'Seed': seed,
        'Key': key.hex()
    }

def save_key_to_mongo(user_id, file_name, algorithm, password, encryption_comps):
    user_collection = db[f"{user_id}_keys"]
    user_collection.insert_one({
        "file_name": file_name,
        "algorithm": algorithm,
        "password": password,
        "key": encryption_comps["Key"],
        "salt": encryption_comps["Salt"],
        "seed": encryption_comps["Seed"],
    })

def handle_client_connection(client_socket):
    try:
        request_data = client_socket.recv(1024).decode()
        data = json.loads(request_data)

        user_id = data.get("user_id")
        file_name = data.get("file_name")
        algorithm = data.get("algorithm")
        password = data.get("password")

        # Validate data
        if not all([user_id, file_name, algorithm, password]):
            client_socket.sendall(json.dumps({"error": "Missing required fields"}).encode())
            return

        encryption_comps = gen_encryption_comps()

        # Save to MongoDB
        save_key_to_mongo(user_id, file_name, algorithm, password, encryption_comps)

        # Send response back
        response = {
            "key": encryption_comps["Key"],
            "salt": encryption_comps["Salt"],
            "seed": encryption_comps["Seed"],
        }
        print(f"Sending response: {response}")
        client_socket.sendall(json.dumps(response).encode())

    except json.JSONDecodeError:
        print(f"Sending response: {response}")
        client_socket.sendall(json.dumps({"error": "Invalid JSON format"}).encode())
    except Exception as e:
        client_socket.sendall(json.dumps({"error": str(e)}).encode())
    finally:
        client_socket.close()

def start_key_gen_server():
    HOST = '127.0.0.1'
    PORT = 65432
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print("Key generator listening on port:", PORT)

        while True:
            client_socket, addr = server_socket.accept()
            print("Connection from:", addr)
            handle_client_connection(client_socket)

if __name__ == "__main__":
    start_key_gen_server()
