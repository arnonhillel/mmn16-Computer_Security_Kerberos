# import socket
# import struct
# import random
# import string
# import os
# from datetime import datetime
#
# import uuid
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.primitives import hashes
#
# # Server address and port
# from utils.encryption import decrypt_aes_key, get_encryption_key
#
# server_address = ('localhost', 1256)
#
#
# def register_client(user_name, password):
#     client_id = b''  # 16-byte client.info identifier
#     version = 1  # Version (1 byte)
#     req_code = 1024  # Request code (2 bytes)
#     payload = user_name + password
#     # Calculate the payload size
#     payload_size = len(payload)
#     # Pack the header
#     header = struct.pack("<16sBHL", client_id, version, req_code, payload_size)
#     # Combine the header and payload
#     message = header + payload
#
#     # Create a socket and connect to the server
#     client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     client_socket.connect(server_address)
#     # Send the combined message (header + payload)
#     client_socket.sendall(message)
#
#     # Receive the header, which is 7 bytes in your case
#     header_data = client_socket.recv(7)
#     # Unpack the header to get the payload size
#     header_format = "<BHL"  # Adjust this format according to your header structure
#     res_version, res_code, res_payload_size = struct.unpack(header_format, header_data)
#     # Receive the payload based on the calculated payload size
#     client_id = client_socket.recv(res_payload_size)
#     if res_code == 1600:
#         print(f"Registration was successful... client id: {client_id}")
#     if res_code == 1601:
#         print(f"Registration failed... client id: {client_id}")
#
#     # Close the socket
#     # client_socket.close()
#     return client_id
#
#
# def generate_nonce():
#     return os.urandom(8)
#
#
# def request_key(client_id):
#     version = 1  # Version (1 byte)
#     req_code = 1027  # Request code (2 bytes)
#     nonce = generate_nonce()
#     payload = b"Printer 20" + b'\0' + nonce
#     # Calculate the payload size
#     payload_size = len(payload)
#     # Pack the header
#     header = struct.pack("<16sBHL", client_id, version, req_code, payload_size)
#     # Combine the header and payload
#     message = header + payload
#
#     # Create a socket and connect to the server
#     client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     client_socket.connect(server_address)
#     # Send the combined message (header + payload)
#     client_socket.sendall(message)
#
#     # Receive the header, which is 7 bytes in your case
#     header_data = client_socket.recv(7)
#     # Unpack the header to get the payload size
#     header_format = "<BHL"  # Adjust this format according to your header structure
#     res_version, res_code, res_payload_size = struct.unpack(header_format, header_data)
#
#     if res_code == 1603:
#         # client id
#         client_id_from_auth_server = client_socket.recv(16)
#         print(f"client_id_from_auth_server: {client_id_from_auth_server}")
#
#         # encrypted_key
#         encrypted_key_size = 16 + 16 + 32
#         encrypted_key_bytes = client_socket.recv(encrypted_key_size)
#         format_string = "16s16s32s"
#         encrypted_iv, encrypted_nonce, encrypted_aes_key, = struct.unpack(format_string, encrypted_key_bytes)
#         # decrypt aes key
#         password_hash = "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f"
#         encryption_key = get_encryption_key(password_hash)
#         decrypted_nonce, decrypted_aes_key = decrypt_aes_key(encrypted_iv, encrypted_nonce, encrypted_aes_key, encryption_key)
#         # save encrypted aes key
#         print(f"decrypted_aes_key {decrypted_aes_key}\n decrypted_nonce: {decrypted_nonce}")
#         # ticket
#         ticket_size = 1 + 16 + 16 + 8 + 16 + 32 + 8
#         ticket_bytes = client_socket.recv(ticket_size)
#         return decrypted_aes_key, ticket_bytes
#         # unpack ticket
#         # format_string = '>B16s16sQ16s32sQ'
#         # version, _id, server_id, creation_time, ticket_iv, aes_key, expiration_time = struct.unpack(format_string,
#         #                                                                                             ticket_bytes)
#     if res_code == 1601:
#         print(f"request key failed... client id: {client_id}")
#
#     # Close the socket
#     # client_socket.close()
#     return None, None
#
#
# def generate_random_name(length):
#     letters = string.ascii_lowercase
#     return ''.join(random.choice(letters) for _ in range(length))
#
#
# # if __name__ == "__main__":
# #     random_name = generate_random_name(10)
# #     name = 'Arnon Hillel'.encode('ascii')[:254] + b'\0'
# #     # name = random_name.encode('ascii')[:254] + b'\0'
# #     password = 'password123'.encode('ascii')[:254] + b'\0'
# #     client_id = register_client(name, password)
# #     aes_key, ticket = request_key(client_id)
# # #     create authenticator
# # #     send authenticator and aes to server
