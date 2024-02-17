import uuid

from datetime import datetime

from utils.protocol import PROTOCOL_VERSION
from utils.ticket import Ticket
from utils import protocol
from utils.encryption import generate_aes_key, encrypt_aes_key_and_nonce, get_encryption_key


def print_banner(param, code, name):
    banner = f"--------------{param}: {code}({name})----------"
    print(get_bold_text(banner))


def get_bold_text(text):
    return f"\033[1m{text}\033[0m"


def handle_auth_request(client_socket, data, client_list, request_header):
    try:
        if data and request_header.code in requestHandle.keys():
            print_banner("New Request", request_header.code,
                         protocol.code_to_request_mapping.get(request_header.code, ""))
            response = requestHandle[request_header.code](data, client_list, request_header)
            if response:
                client_socket.sendall(response)
            client_socket.close()
    except Exception as e:
        print(f"Error handling client: {e}")
        client_socket.close()
    finally:
        client_socket.close()


# Register Client
def handle_client_registration_request(data, client_list, request_header):
    response = protocol.ClientRegistrationResponse()
    try:
        request = protocol.ClientRegistrationRequest(request_header)
        if not request.unpack(data):
            raise ValueError("Failed parsing request.")
        if client_list.get_client_by_name(request.name):
            raise ValueError("Client already exists.")
        ID = uuid.uuid4().bytes
        name = request.name
        password = request.password
        last_seen = datetime.now().timestamp()
        client_data = client_list.add_client(ID, name, password, last_seen)
        if client_data:
            response.client_id = client_data.ID
            response.header.payloadSize = protocol.CLIENT_ID_SIZE
            print(f"Successfully registered new client \nclient name: {request.name}.")
            return response.pack()
    except ValueError as ve:
        print(f"Registration Request: {ve}")
        response.header.code = protocol.EResponseCode.RESPONSE_REGISTRATION_ERROR.value
        return response.pack()

    except Exception as e:
        print(f"Registration Request: Failed to store client. {e}")
        response.header.code = protocol.EResponseCode.RESPONSE_REGISTRATION_ERROR.value
        return response.pack()


def handle_symmetric_key_request(data, client_list, request_header):
    response = protocol.SymmetricKeyForClientResponse()
    try:
        request = protocol.SymmetricKeyForClientRequest(request_header)
        if not request.unpack(data):
            raise ValueError("Failed parsing request.")
        client_id = request.header.client_id
        aes_key = generate_aes_key()
        response.client_id = client_id
        response.encrypted_key = get_client_encrypted_key(aes_key, client_list, client_id, request.nonce)
        response.ticket = get_server_ticket(aes_key, client_id)
        print(f"Successfully send symmetric key \nclient id: {client_id}.")
        return response.pack()
    except ValueError as ve:
        print(f"Symmetric Key Request: {ve}")
        response.header.code = protocol.EResponseCode.RESPONSE_SYMMETRIC_KEY_ERROR.value
        return response.pack()
    except Exception as e:
        print(f"Symmetric Key Request: Failed to handle request. {e}")
        response.header.code = protocol.EResponseCode.RESPONSE_REGISTRATION_ERROR.value
        return response.pack()


def get_client_encrypted_key(aes_key, client_list, client_id, nonce):
    client_hash = client_list.get_client_by_id(client_id).password
    client_encryption_key = get_encryption_key(client_hash)
    encrypted_aes_key_for_client = encrypt_aes_key_and_nonce(aes_key, client_encryption_key, nonce)
    return encrypted_aes_key_for_client


def get_server_ticket(aes_key, client_id):
    server_version = PROTOCOL_VERSION
    ticket = Ticket(server_version, client_id, aes_key)
    return ticket.pack()


ERequestCode = protocol.ERequestCode
requestHandle = {
    ERequestCode.REQUEST_CLIENT_REGISTRATION.value: handle_client_registration_request,
    ERequestCode.REQUEST_SYMMETRIC_KEY.value: handle_symmetric_key_request
}
