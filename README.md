# MMN 16 - README

## Authors
`Arnon Hillel`


## Introduction - Kerberos Implementation
This project implements a simplified version of the Kerberos protocol, consisting of three services: auth_service, client, and msg_service.
- `auth_service` This service manages user registration and issues tickets for authentication purposes.
- `client` The client component interacts with the auth_service to acquire authentication tickets and securely communicates with the msg_service.
- `msg_service` The message service acts as a printing server. It receives authentication requests and encrypted messages from clients, decrypts them using tickets obtained from the auth_service, and displays them on the screen.

# Overview 
- `Client --> auth_service: IDs, Nonce`
- `auth_service --> Client: EKc(Kc,s, Nonce), Ticket`
- `Client -->msg_service: Ticket, Authenticator`
- `msg_service -->Client: KeyAck`
- `Client --> msg_service: EKc,s(Message)`
- `msg_service -->Client: MsgAck`

This document serves as a guide for setting up and running each service independently,
providing clear instructions to ensure smooth execution and comprehension of the project's functionality.


## Prerequisites
- Python 3.x installed on your system


## Project Structure

```
mmn16-/
|-- auth_service/
|   |-- utils/
|   |   |-- encryption.py
|   |   |-- protocol.py
|   |   |-- string_util.txt
|   |   |-- ticket.py
|   |-- auth_service.py
|   |-- client_list.py
|   |-- client.txt
|   |-- main.py
|   |-- msg.info
|   |-- port.info
|   |-- server_list.py
|
|-- client/
|   |-- utils/
|   |   |-- authenticator.py
|   |   |-- encryption.py
|   |   |-- protocol.py
|   |   |-- string_util.txt
|   |-- client.py
|   |-- client_auth.py
|   |-- client_msg.py
|   |-- connection.py
|   |-- me.info
|   |-- srv.info
|
|-- msg_service/
|   |-- utils/
|   |   |-- authenticator.py
|   |   |-- encryption.py
|   |   |-- protocol.py
|   |   |-- string_util.txt
|   |   |-- ticket.py
|   |-- main.py
|   |-- message_service.py
|   |-- msg.info.py
|   |-- msg.info
|   |-- port.info
|
|-- Q2/
|   |-- dict_attack.py
|   |-- wordlist.txt
|-- README.md
```

## Running Services

### 1. auth_service
1. Navigate to the `auth_service` directory.
2. Run the following command:
    ```
    python main.py
    ```


### 2. msg_service
1. Navigate to the `msg_service` directory.
2. Run the following command:
    ```
    python main.py
    ```

### 3. client
1. Before running the client, ensure that both `auth_service` and `msg_service` are running.
2. Navigate to the `client` directory.
3. Run the following command:
    ```
    python main.py
    ```

### 4. Question 2
1. Loads a wordlist from a file specified as an argument to the load_words_and_hash function.
2. Hashes each word in the wordlist using the SHA-256 hashing algorithm.
3. Derives an encryption key from each hashed password using the PBKDF2 function.
4. Attempts to decrypt a nonce received from the server using each encryption key derived from the hashed passwords.
5. If the decrypted nonce matches the client-generated nonce, the corresponding password is considered found, and its hash is printed along with the password itself.

##Note.
This script is provided for educational and legitimate security testing purposes only. It is not intended for use in any illegal, unethical, or unauthorized activities. Unauthorized access to computer systems, networks, or data is illegal and unethical.

By using this script, you agree to adhere to the principles of responsible and ethical use. The developers and contributors of this script are not liable for any misuse or unlawful activities conducted with this code.
![alt text](mmn16.png)