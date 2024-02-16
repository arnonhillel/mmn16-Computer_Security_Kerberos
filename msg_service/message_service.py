from utils import protocol
from utils.authenticator import Authenticator
from utils.encryption import decrypt_data
from utils.string_util import base64_to_string
from utils.ticket import Ticket
import socket
import threading
from utils.protocol import CLIENT_ID_SIZE, VERSION_SIZE, CODE_SIZE, PAYLOAD_SIZE, RequestHeader


def print_banner(param, code, name):
    banner = f"--------------{param}: {code}({name})----------"
    print(get_bold_text(banner))


def print_message(client_id, msg):
    banner = f"--------------Message From {client_id}:\n {msg}----------"
    print(get_bold_text(banner))


def get_bold_text(text):
    return f"\033[1m{text}\033[0m"


def handle_request(client_socket, data, request_header):
    try:
        if data and request_header.code in requestHandle.keys():
            print_banner("New Request", request_header.code,
                         protocol.code_to_request_mapping.get(request_header.code, ""))
            response = requestHandle[request_header.code](data, request_header)
            if response:
                client_socket.sendall(response)
            client_socket.close()
    except Exception as e:
        print(f"Error handling client: {e}")
        client_socket.close()
    finally:
        client_socket.close()


# send symmetric key
def is_valid_authenticator(authenticator):
    pass


def is_valid_ticket(ticket):
    pass


def handle_send_symmetric_key_request(data, request_header):
    response = protocol.SymmetricKeyForMsgSrvResponse()
    try:
        request = protocol.SymmetricKeyForMsgSrvRequest(request_header)
        msg_server_info = load_msg_info()
        if not request.unpack(data):
            raise ValueError("Failed parsing request.")
        # authenticator = Authenticator.unpack(request.authenticator, base64_to_string(msg_server_info.key))
        ticket = Ticket.unpack(request.ticket, base64_to_string(msg_server_info.key))
        decrypted_aes_key = decrypt_data(ticket.aes_key, base64_to_string(msg_server_info.key), ticket.ticket_iv)
        print(decrypted_aes_key)
        # # TODO decrypt authenticator with decrypted_aes_key
        # if is_valid_authenticator(authenticator) and is_valid_ticket(ticket):
        #     return response.pack()
        return response.pack()
    except ValueError as ve:
        print(f"Registration Request: {ve}")
        response.header.code = protocol.EResponseCode.RESPONSE_REGISTRATION_ERROR.value
        return response.pack()


def handle_message_from_client_request(data, request_header):
    response = protocol.NewMessageResponse()
    try:
        request = protocol.NewMessageRequest(request_header)
        if not request.unpack(data):
            raise ValueError("Failed parsing request.")
        # TODO decrypt message
        print(f"{request.header.client_id} message: {request.message_content}")
        return response.pack()
    except ValueError as ve:
        print(f"Registration Request: {ve}")
        response.header.code = protocol.EResponseCodeMsgService.RESPONSE_SERVER_ERROR.value
        return response.pack()


ERequestCode = protocol.ERequestCodeMsgService
requestHandle = {
    ERequestCode.REQUEST_SYMMETRIC_KEY.value: handle_send_symmetric_key_request,
    ERequestCode.REQUEST_SEND_MESSAGE.value: handle_message_from_client_request,
}


class MsgInfo:
    def __init__(self, address, name, server_id, key):
        self.address = address
        self.name = name
        self.server_id = server_id
        self.key = key


MSG_INFO_PATH = "msg.info"


def load_msg_info():
    try:
        with open(MSG_INFO_PATH, 'r') as file:
            lines = file.readlines()

            # Extracting data from lines
            address = lines[0].strip()
            name = lines[1].strip()
            server_id = lines[2].strip()
            key = lines[3].strip()

            return MsgInfo(address, name, server_id, key)
    except FileNotFoundError:
        print(f"File '{MSG_INFO_PATH}' not found.")
    except Exception as e:
        print(f"An error occurred while reading '{MSG_INFO_PATH}': {e}")
    return None
