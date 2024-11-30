import os
import json
import socket
from pymongo import MongoClient
from dotenv import load_dotenv

# Load environment variables from the .env file
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB_NAME = MONGO_URI.split("/")[-1].split("?")[0]

# Set up MongoDB connection
try:
    client = MongoClient(MONGO_URI)
    db = client[MONGO_DB_NAME]
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")
    exit()

# Function to handle client requests
def client_handler(client_socket):
    try:
        # Receive data from the client
        request_data = client_socket.recv(1024).decode()
        if not request_data:
            return
        
        # Parse the received data
        login_request = json.loads(request_data)
        username = login_request.get("username")
        password = login_request.get("password")

        # Validate if data exists
        if not username or not password:
            response = {"status": "error", "message": "Username or password missing"}
            client_socket.sendall(json.dumps(response).encode())
            return

        # Query MongoDB for the user
        user = db["users"].find_one({"username": username})

        if user and user["password"] == password:
            # Authentication successful
            response = {
                "status": "success",
                "user": {
                    "id": user["id"],
                    "username": user["username"],
                    "email": user["email"]
                }
            }
        else:
            # Authentication failed
            response = {"status": "failure", "message": "Invalid username or password"}

        # Send the response to the client
        client_socket.sendall(json.dumps(response).encode())
    
    except Exception as e:
        # Handle any unexpected errors
        response = {"status": "error", "message": f"An error occurred: {str(e)}"}
        client_socket.sendall(json.dumps(response).encode())
    
    finally:
        # Close the client socket connection
        client_socket.close()

# Main function to start the server
def main():
    HOST = "127.0.0.1"
    PORT = 65431

    # Create a socket and bind it to the host and port
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)

    print(f"Login microservice listening on {HOST}:{PORT}...")

    try:
        while True:
            # Accept incoming client connections
            client_socket, addr = server_socket.accept()
            print(f"Connection received from {addr}")
            
            # Handle the client connection
            client_handler(client_socket)
    
    except KeyboardInterrupt:
        print("Shutting down the server...")
    finally:
        server_socket.close()
        client.close()

if __name__ == "__main__":
    main()
