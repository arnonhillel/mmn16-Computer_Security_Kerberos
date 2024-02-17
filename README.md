# MMN 16 - README

## Authors
`Arnon Hillel & Alon Nissim`


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
