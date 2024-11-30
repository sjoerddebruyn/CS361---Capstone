import os
import json
import socket
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from pymongo import MongoClient
from dotenv import load_dotenv
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding

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

def encrypt_algorithm(file_name, file_content, algorithm, encryption_comps):
    if algorithm.upper() == "AES":
        try:
            key = encryption_comps.get("key")
            iv = encryption_comps.get("iv")
            # Padding
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(file_content.encode()) + padder.finalize()

            # Encryption
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            # Combine IV and encrypted data
            combined_data = iv + encrypted_data

            # Base64 encode the combined data
            encoded_data = base64.b64encode(combined_data).decode("utf-8")

            return {
                "file_name": file_name,
                "encrypted_data": encoded_data
            }

        except Exception as e:
            return {"error": str(e)}

    elif algorithm.upper() == "RSA":
        try:
            public_key = RSA.import_key(encryption_comps['public_key'].encode('utf-8'))
            cipher_rsa = PKCS1_OAEP.new(public_key)
            encrypted_data = cipher_rsa.encrypt(file_content.encode())
            encoded_data = base64.b64encode(encrypted_data).decode("utf-8")

            return {
                "file_name": file_name,
                "encrypted_data": encoded_data,
            }
        except Exception as e:
            return {"error": str(e)}

    elif algorithm.upper() == "ECC":
        try:
            private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            public_key = private_key.public_key()

            # Encrypt the file content using ECC encryption (ECDSA signature for simplicity)
            encrypted_data = public_key.encrypt(
                file_content.encode(),
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Return the encrypted data and the public key for the recipient to decrypt
            encoded_data = base64.b64encode(encrypted_data).decode("utf-8")
            return {
                "file_name": file_name,
                "encrypted_data": encoded_data,
                "public_key": public_key
            }

        except Exception as e:
            return {"error": str(e)}

    else:
        raise ValueError(f"Algorithm type: {algorithm} is not supported. ")

def decrypt_algorithm(user_id, file_name, password):
    try:
        user_collection_name = f"user{user_id}"
        user_collection = db[user_collection_name]

        file_record = user_collection.find_one({"file_name": file_name})
        if not file_record:
            return {"error": "file not found"}

        stored_password = file_record["password"]
        encrypt_algorithm = file_record["algorithm"]

        if password != stored_password:
            return {"error": "incorrect decryption password"}

        if encrypt_algorithm == "AES":
            # Base64 decode the encrypted data and iv
            encrypted_data = base64.b64decode(file_record["encrypted_data"])
            iv = encrypted_data[:16]  # Extract the IV (first 16 bytes)
            encrypted_file_content = encrypted_data[16:]  # Extract the encrypted file content

            # Decrypt the file content
            cipher = Cipher(algorithms.AES(file_record["key"].encode()), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_file_content) + decryptor.finalize()

            # Unpad the decrypted data
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

            return {"decrypted_file": unpadded_data.decode()}

        elif encrypt_algorithm == "RSA":
            pass  # RSA decryption code here

        elif encrypt_algorithm == "ECC":
            try:
                private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
                encrypted_data = base64.b64decode(file_record["encrypted_data"])

                decrypted_data = private_key.decrypt(
                    encrypted_data,
                    asymmetric_padding.OAEP(
                        mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                return {"decrypted_file": decrypted_data.decode()}

            except Exception as e:
                return {"error": str(e)}

    except Exception as e:
        return {"error": str(e)}

def handle_client_connection(client_socket):
    try:
        request_data = client_socket.recv(1024).decode()
        data = json.loads(request_data)

        service_type = data.get("service_type")

        # If service is encrypt (e)
        if service_type == "e":
            file_name = data.get("file_name")
            file_content = data.get("file_content")
            algorithm = data.get("algorithm")
            if algorithm == "AES" or algorithm == "ECC":
                key = base64.b64decode(data.get("key"))  # Decode Base64 key
                iv = base64.b64decode(data.get("iv"))  # Decode Base64 IV
                encryption_comps = {
                    "key": key,
                    "iv": iv,
                }
            elif algorithm == "RSA":
                public_key = data.get("public_key")
                private_key = data.get("private_key")
                encryption_comps = {
                    "public_key": public_key,
                    "private_key": private_key,
                }

            encrypted_file = encrypt_algorithm(file_name, file_content, algorithm, encryption_comps)

            if "error" in encrypted_file:
                response = {"error": encrypted_file["error"]}
            else:
                response = {
                    "file_name": encrypted_file["file_name"],
                    "encrypted_file": encrypted_file["encrypted_data"],
                }

        # If service is decrypt (d)
        elif service_type == "d":
            user_id = data.get("user_id")
            file_name = data.get("file_name")
            password = data.get("password")
            decrypted_file = decrypt_algorithm(user_id, file_name, password)

            if "error" in decrypted_file:
                response = {"error": decrypted_file["error"]}
            else:
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
