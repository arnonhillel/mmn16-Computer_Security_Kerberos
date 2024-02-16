# MMN 16 - README

## Authors
`Arnon Hillel & Alon Nissim`


## Introduction
This project contains three services: `auth_service`, `client`, and `msg_service`. This README provides instructions on how to run each service separately.

## Prerequisites
- Python 3.x installed on your system


## Project Structure

```
mmn16-/
|-- auth_service/
|   |-- utils/
|   |   |-- authenticator.py
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
|-- client/
|   |-- utils/
|   |   |-- authenticator.py
|   |   |-- encryption.py
|   |   |-- protocol.py
|   |   |-- string_util.txt
|   |   |-- ticket.py
|   |-- client.py
|   |-- client_auth.py
|   |-- client_msg.py
|   |-- connection.py
|   |-- me.info
|   |-- srv.info
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

## Additional Notes
- TODO
