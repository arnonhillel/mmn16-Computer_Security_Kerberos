from utils.encryption import hash_password


CLIENTS_PATH = "clients.txt"


class ClientList:
    def __init__(self):
        self.clients = self.load_clients()

    def load_clients(self):
        clients = []
        try:
            with open(CLIENTS_PATH, "r") as file:
                for line in file:
                    fields = line.strip().split(":")
                    client = Client(fields[0], fields[1], fields[2], fields[3])
                    clients.append(client)
            return clients
        except FileNotFoundError:
            print("Clients file not found.")
            return []
        except Exception as e:
            print(f"An error occurred while reading clients file: {e}")
            return []

    def save_clients_to_file(self, client):
        try:
            with open(CLIENTS_PATH, "a") as file:
                line = f"{client.ID}:{client.name}:{client.password}:{client.last_seen}\n"
                file.write(line)
            return True
        except Exception as e:
            print(f"An error occurred while saving client to file: {e}")
            return False

    def add_client(self, ID, name, password, last_seen):
        password_hash = hash_password(password)
        new_client = Client(ID, name, password_hash, last_seen)
        self.clients.append(new_client)
        if self.save_clients_to_file(new_client):
            return new_client
        else:
            return None

    def remove_client(self, client):
        self.clients.remove(client)

    def get_client_by_id(self, _id):
        for client in self.clients:
            if client.ID == _id or client.ID == str(_id):
                return client
        return None

    def get_client_by_name(self, name):
        for client in self.clients:
            if client.name == name:
                return client
        return None

    def get_all_clients(self):
        return self.clients


class Client:
    def __init__(self, ID, name, password, last_seen):
        self.ID = ID
        self.name = name
        self.password = password
        self.last_seen = last_seen
