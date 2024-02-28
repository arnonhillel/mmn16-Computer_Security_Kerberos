import socket
import threading
from message_service import handle_request

from utils.protocol import CLIENT_ID_SIZE, VERSION_SIZE, CODE_SIZE, PAYLOAD_SIZE, RequestHeader


def get_port_from_file(file_path='port.info', default_port='1235'):
    try:
        with open(file_path, 'r') as file:
            port = file.readline().strip()
            if not port:
                raise ValueError("Port not found in the file.")
    except FileNotFoundError:
        print(f"File not found: {file_path}. Using default port: {default_port}")
        port = default_port
    except Exception as e:
        print(f"An error occurred: {e}. Using default port: {default_port}")
        port = default_port
    return int(port)


def get_msg_server_details(file_path='msg.info'):
    try:
        with open(file_path, 'r') as file:
            port = file.readline().strip()
            if not port:
                raise ValueError("Port not found in the file.")
    except FileNotFoundError:
        print(f"File not found: {file_path}.")
    except Exception as e:
        print(f"An error occurred: {e}.")
    return int(port)


def main():
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("0.0.0.0", get_port_from_file()))
        server.listen(5)
        print(f"[*] Listening on {get_port_from_file()}")

        while True:
            client_socket, addr = server.accept()
            print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")
            client_id = client_socket.recv(CLIENT_ID_SIZE)
            version = int.from_bytes(client_socket.recv(VERSION_SIZE), byteorder='little', signed=False)
            code = int.from_bytes(client_socket.recv(CODE_SIZE), byteorder='little', signed=False)
            payload_size = int.from_bytes(client_socket.recv(PAYLOAD_SIZE), byteorder='little', signed=False)
            request_header = RequestHeader(client_id, version, code, payload_size)
            data = b""
            remaining_bytes = payload_size
            while remaining_bytes > 0:
                block = client_socket.recv(1024)
                data += block
                remaining_bytes -= 1024
            client_handler = threading.Thread(target=handle_request, args=(client_socket, data, request_header,))
            client_handler.start()
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
