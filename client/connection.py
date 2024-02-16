import socket


class Connection:
    def __init__(self, server_address, server_port):
        self.server_address = server_address
        self.server_port = server_port
        self.client_socket = None

    def connect(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.server_address, self.server_port))
            print("Connected to authentication service at:", self.server_address, "on port:", self.server_port)
            return True
        except Exception as e:
            print("Error connecting to authentication service:", e)
            return False

    def send_data(self, data):
        try:
            self.client_socket.sendall(data)
            # print("Data sent successfully")
            return True
        except Exception as e:
            print("Error sending data:", e)
            return False

    def receive_data(self, buffer_size):
        try:
            data = self.client_socket.recv(buffer_size)
            # print("Data received:", data)
            return data
        except Exception as e:
            print("Error receiving data:", e)
            return None

    def close_connection(self):
        try:
            self.client_socket.close()
            print("Connection closed")
            return True
        except Exception as e:
            print("Error closing connection:", e)
            return False