import os
import json
import socket
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
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

def encrypt_algorithm(file_name, file_content, key, iv, algorithm):
    if algorithm.upper() == "AES":
        try:
            # padding
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(file_content.encode()) + padder.finalize()

            # encryption
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend = default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            combined_data = iv + encrypted_data

            encoded_data = base64.b64decode(combined_data).decode("utf-8")

            return {
                "file_name": file_name,
                "encrypted_data": encoded_data
            }

        except Exception as e:
            return {"error": str(e)}
    elif algorithm.upper() == "RSA":
        return {"error": "RSA not yet implemented"}
    elif algorithm.upper() == "SHA-512":
        return {"error": "SHA-512 not yet implemented"}
    else:
        raise ValueError(f"Algorithm type: {algorithm} is not supported. ")

def decrypt_algorithm(user_id, file_name, password):
    try: 
        user_collection_name = f"user{user_id}"
        user_collection = db[user_collection_name]

        file_record = user_collection.find_one(file_name)
        if not file_record:
            return {"error": "file not found"}
        
        stored_password = file_record["password"]
        encrypt_algorithm = file_record["algorithm"]

        if password == stored_password:
            return {"error": "incorrect decryption password"}
        
        if encrypt_algorithm == "AES":
            pass

        elif encrypt_algorithm == "RSA":
            pass

        elif encrypt_algorithm == "SHA512":
            pass
    except Exception as e:
        return {"error": str(e)}
    
def handle_client_connection(client_socket):
    try:
        request_data = client_socket.recv(1024).decode()
        data = json.loads(request_data)

        service_type = data.get("service_type")

        # if service is e then encrypt
        if service_type == "e":
            file_name = data.get("file_name")
            file_content = data.get("file_content")
            key = data.get("key")
            iv = data.get("iv")
            algorithm = data.get("algorithm")
            encrypted_file = encrypt_algorithm(file_name, file_content, key, iv, algorithm)
            if "error" in encrypted_file:
                response = {"error": encrypted_file["error"]}
            else:
                response = {
                "file_name": encrypted_file["file_name"],
                "encrypted_file": encrypted_file["encrypted_data"],
            }

        # if service is d then decrypt
        elif service_type == "d":
            user_id = data.get("user_id")
            file_name = data.get("file_name")
            password = data.get("password")
            decrypted_file = decrypt_algorithm(user_id, file_name, password)
            response = {
                "decrypted_file": decrypted_file,
            }

        print(f"Sending response: {response}")
        client_socket.sendall(json.dumps(response).encode())


    except Exception as e:
        client_socket.sendall(json.dumps({"error": str(e)}).encode())
    finally:
        client_socket.close()

def start_encryption_service():
    HOST = "127.0.0.1"
    PORT = 65433
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"Server listening on port: {PORT}")

        while True: 
            client_socket, addr = server_socket.accept()
            print(f"Client address: {addr}")
            handle_client_connection(client_socket)

if __name__ == "__main__":
    start_encryption_service()