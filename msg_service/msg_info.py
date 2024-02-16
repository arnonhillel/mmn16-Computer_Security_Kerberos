class MsgInfo:
    def __init__(self, address,port, name, server_id, key):
        self.address = address
        self.port = port
        self.name = name
        self.server_id = server_id
        self.key = key


MSG_INFO_PATH = "msg.info"


def get_msg_info():
    try:
        with open(MSG_INFO_PATH, 'r') as file:
            lines = file.readlines()

            # Extracting data from lines
            address, port = lines[0].strip().split(":")
            name = lines[1].strip()
            server_id = lines[2].strip()
            key = lines[3].strip()

            return MsgInfo(address, port, name, server_id, key)
    except FileNotFoundError:
        print(f"File '{MSG_INFO_PATH}' not found.")
    except Exception as e:
        print(f"An error occurred while reading '{MSG_INFO_PATH}': {e}")
    return None
