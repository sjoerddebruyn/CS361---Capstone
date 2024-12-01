import socket
import json

HOST = '127.0.0.1'
PORT = 65430
BUFFER_SIZE = 128

# Predefined flag-to-message mapping
messages = {
    'rs': 'Registration was successful',
    'rf': 'Registration has failed',
    'ls': 'Login was successful',
    'lf': 'Login has failed',
    'es': 'Encryption was successful',
    'ef': 'Encryption has failed',
    'ds': 'Decryption was successful',
    'df': 'Decryption has failed'
}

def start_notification_service():
    # Initialize TCP/IP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"Notification service is listening on {HOST}:{PORT}")

        while True:
            conn, addr = server_socket.accept()
            with conn:
                try:
                    # Receive data and parse the JSON
                    data = conn.recv(BUFFER_SIZE).decode().strip()
                    request = json.loads(data)
                    flag = request.get("flag")

                    # Determine response based on the flag
                    if flag in messages:
                        response = {
                            "message": messages[flag],
                            "status": "success"
                        }
                    else:
                        response = {
                            "message": "Error: Unrecognized operation",
                            "status": "failure"
                        }

                    print(f"Received: {flag}, Responding: {response}")
                    conn.sendall(json.dumps(response).encode())
                except json.JSONDecodeError:
                    error_response = {"message": "Invalid JSON format", "status": "error"}
                    conn.sendall(json.dumps(error_response).encode())

if __name__ == "__main__":
    start_notification_service()
