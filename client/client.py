from client_msg import send_symmetric_key, send_message_to_msg_server
from client_auth import register_client, request_key_and_ticket
from utils import protocol
from utils.authenticator import Authenticator
from connection import Connection
from Crypto.Random import get_random_bytes

AUTH_SERVER_ADDRESS = '127.0.0.1'
AUTH_SERVER_PORT = 1256
MSG_SERVER_ADDRESS = '127.0.0.1'
MSG_SERVER_PORT = 1235
MSG_SERVER_ID = "64f3f63985f04beb81a0e43321880182"


def create_iv():
    return get_random_bytes(16)


def get_auth_connection():
    auth_service = Connection(AUTH_SERVER_ADDRESS, AUTH_SERVER_PORT)
    auth_service.connect()
    return auth_service


def get_msg_srv_connection():
    auth_service = Connection(MSG_SERVER_ADDRESS, MSG_SERVER_PORT)
    auth_service.connect()
    return auth_service


def save_client_id_to_file(file_path, _id):
    try:
        with open(file_path, 'r+') as file:
            content = file.read()
            file.seek(0)
            file.write(content + '\n' + _id)
        print("Client ID saved successfully.")
    except FileNotFoundError:
        print("Error: File not found.")
    except PermissionError:
        print("Error: Permission denied. Make sure you have write access to the file.")
    except Exception as e:
        print(f"Error saving client ID to file: {e}")


def register_or_load_data_from_me_info(file_path):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            _name, _password = lines[0].strip().split('@')
            # encode
            _name = _name.encode('ascii')[:254] + b'\0'
            _password = _password.encode('ascii')[:254] + b'\0'

            _id = bytes.fromhex(lines[1].strip()) if len(lines) > 1 else None
            if _id is None or _id == b"":  # not None if client already registered
                _id = register_client(get_auth_connection(), _name, _password)
                if _id is not None:
                    save_client_id_to_file('me.info', _id.hex())
                else:
                    print("Failed to register the client.")
                    exit()
            return _name, _password, _id
    except FileNotFoundError:
        print("File not found.")
        return None, None, None
    except Exception as e:
        print("Error loading data:", e)
        return None, None, None


def run_client():
    try:
        """
        Communication with Authentication Service
        """
        server_id_bytes = bytes.fromhex(MSG_SERVER_ID)
        """ ***** Register or Load data from 'me.info' file if user already registered.  *****"""
        name, password, client_id = register_or_load_data_from_me_info('me.info')
        """ ***** Request Symmetric Key From Auth to communicate with Message Service  *****"""
        decrypted_aes_key_client_msg, ticket_bytes = request_key_and_ticket(get_auth_connection(), client_id,
                                                                            password.decode('utf-8').strip(
                                                                                '\x00').strip("'"),
                                                                            server_id_bytes)
    except Exception as e:
        print(f"Error during communication with Authentication Service: {e}")
    else:
        """
        Communication with Message Service
        """
        try:
            """ ***** Send Encrypted Symmetric Key  *****"""
            if decrypted_aes_key_client_msg is not None and ticket_bytes is not None:
                # Create and pack authenticator
                authenticator = Authenticator(protocol.PROTOCOL_VERSION, client_id, server_id_bytes)
                authenticator_bytes = authenticator.pack(decrypted_aes_key_client_msg)

                # Send symmetric key to message service
                is_symmetric_key_sent = send_symmetric_key(get_msg_srv_connection(), client_id, authenticator_bytes,
                                                           ticket_bytes)

                if is_symmetric_key_sent:
                    print('Symmetric key sent successfully.')
                    while True:
                        """ ***** Send Encrypted Message *****"""
                        message = input("Enter your message (type 'exit' to quit): ")
                        if message.lower() == 'exit':
                            print('Exiting...')
                            break
                        is_message_sent = send_message_to_msg_server(get_msg_srv_connection(), client_id,
                                                                     message.encode('utf-8'),
                                                                     decrypted_aes_key_client_msg)
                        if is_message_sent:
                            print('Message Sent successfully.')
                        else:
                            print('Failed to send Message.')

                else:
                    print('Failed to send symmetric key.')
            else:
                print("Error: Failed to retrieve AES key or ticket from authentication service.")

        except Exception as e:
            print(f"Error during communication with Message Service: {e}")


if __name__ == "__main__":
    run_client()
