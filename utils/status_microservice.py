import socket

HOST = '127.0.0.1'
PORT = 65430
BUFFER_SIZE = 128 

# Message dictionary, feel free to change to whatever flag syntax will be used
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
    # Init TCP/IP socket 
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT)) 
        server_socket.listen()
        print(f"status service is listening on {HOST}:{PORT}")

        while True:
            conn, addr = server_socket.accept()
            with conn:
                flag = conn.recv(BUFFER_SIZE).decode().strip()

                if flag in messages:
                    response = {
                        "message": messages[flag],
                        "status": "success"
                    }
                else:
                    # If the flag is unrecognized, return default err msg
                    response = {
                        "message": "Error: Unrecognized operation",
                        "status": "failure"
                    }

                print(response)
                conn.sendall(str(response).encode())  # Return response to client

if __name__ == "__main__":
    start_notification_service()