import json
import socket
import os
import hashlib
import hmac
import secrets
import base64
from pymongo import MongoClient
from dotenv import load_dotenv
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

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

# AES/ECC encryption comp creator
def salt_gen(length=16):
    return os.urandom(length)

def seed_gen():
    return secrets.token_hex(16)

def key_gen(salt, seed, length=32):
    return hmac.new(salt, seed.encode(), hashlib.sha256).digest()[:length]

def iv_gen():
    return os.urandom(16)

def aes_ecc_gen_encryption_comps():
    salt = salt_gen()
    seed = seed_gen()
    key = key_gen(salt, seed)
    iv = iv_gen()
    return {
        'salt': base64.b64encode(salt).decode('utf-8'),
        'seed': seed,
        'key': base64.b64encode(key).decode('utf-8'),
        'iv': base64.b64encode(iv).decode('utf-8')
    }

# RSA encryption comp creator
def rsa_gen_encryption_comps():
    key = RSA.generate(2048)
    public_key = key.publickey().export_key().decode('utf-8')  # Convert to string
    private_key = key.export_key().decode('utf-8')            # Convert to string
    return {
        'public_key': public_key,
        'private_key': private_key
    }

# ECC key generation
def ecc_gen_encryption_comps():
    # Generate ECC private and public keys using SECP256R1 curve
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    # Serialize the keys to PEM format for storage
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return {
        'private_key': private_key_pem,
        'public_key': public_key_pem
    }

def save_key_to_mongo(user_id, file_name, algorithm, password, encryption_comps):
    user_collection = db[f"{user_id}_keys"]
    if algorithm == "AES" or algorithm == "ECC":
        user_collection.insert_one({
            "file_name": file_name,
            "algorithm": algorithm,
            "password": password,
            "key": encryption_comps["key"], 
            "iv": encryption_comps["iv"],
        })
    elif algorithm == "RSA": 
        user_collection.insert_one({
            "file_name": file_name,
            "algorithm": algorithm,
            "password": password,
            "public_key": encryption_comps["public_key"],
            "private_key": encryption_comps["private_key"]
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

        if algorithm == "AES" or algorithm == "ECC":
            encryption_comps = aes_ecc_gen_encryption_comps()
        elif algorithm == "RSA":
            encryption_comps = rsa_gen_encryption_comps()
        elif algorithm == "ECC":
            encryption_comps = ecc_gen_encryption_comps()

        # Save to MongoDB
        save_key_to_mongo(user_id, file_name, algorithm, password, encryption_comps)

        # Send response back
        if algorithm == "AES" or algorithm == "ECC":
            response = {
                "key": encryption_comps["key"],
                "iv": encryption_comps["iv"]
            }
        elif algorithm == "RSA":
            response = {
                "public_key": encryption_comps["public_key"],
                "private_key": encryption_comps["private_key"]
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
