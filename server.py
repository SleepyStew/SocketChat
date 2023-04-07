import socket
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from hybrid_rsa_aes import HybridCipher

localPrivateKey = rsa.generate_private_key(
    public_exponent=65537, key_size=2048, backend=default_backend()
)
localPublicKey = localPrivateKey.public_key()

print(localPublicKey)

header = 64
port = 30012

build = "2.2 Secure"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("", port))
print(f"Bound to port {port}")
server.listen()

accounts = [
    {"username": "sleepy", "password": "pass1"},
    {"username": "test", "password": "pass2"},
    {"username": "test1", "password": "pass3"},
]
accounts_with_client_data = []

for account in accounts:
    accounts_with_client_data.append(
        {
            "username": account["username"],
            "password": account["password"],
            "client": None,
            "public_key": None,
        }
    )


def encrypt(message, clientPublicKey):
    encrypted_message = (
        HybridCipher()
        .encrypt(data=message, rsa_public_key=clientPublicKey)
        .encode("utf-8")
    )
    return encrypted_message


def decrypt(encrypted_message):
    decrypted_message = HybridCipher().decrypt(
        cipher_text=encrypted_message.decode("utf-8"), rsa_private_key=localPrivateKey
    )
    return decrypted_message


def recieve_string_from_client(client):
    try:
        message_length = client.recv(header).decode("utf-8")
        recieved_message = decrypt(client.recv(int(message_length)))
        print(recieved_message)
        return recieved_message
    except Exception as e:
        print(e)
        return "error"


def send_string_to_client(client, message, clientPublicKey):
    try:
        client.send(
            str(len(encrypt(message, clientPublicKey))).zfill(header).encode("utf-8")
        )
        client.send(encrypt(message, clientPublicKey))
    except Exception as e:
        print(e)
        return "error"


def send_message_to_client(client, message, clientPublicKey):
    try:
        message = "MESSAGE|" + message
        client.send(
            str(len(encrypt(message, clientPublicKey))).zfill(header).encode("utf-8")
        )
        client.send(encrypt(message, clientPublicKey))
    except Exception as e:
        print(e)
        return "error"


def broadcast(message):
    for client_data in accounts_with_client_data:
        if client_data["client"] != None:
            send_message_to_client(
                client_data["client"], message, client_data["public_key"]
            )


def handle(account_login):
    while True:
        message = recieve_string_from_client(account_login["client"])
        account_id = accounts_with_client_data.index(account_login)

        if message == "error":
            account_login["client"].close()
            accounts_with_client_data[account_id]["client"] = None
            accounts_with_client_data[account_id]["public_key"] = None

            broadcast(f"LOG | {account_login['username']} left the chat.")
            break

        # Global Prefix List

        if message.startswith("MESSAGE|"):
            broadcast(account_login["username"] + " > " + message[8:])


def recieve():
    def client():
        client, address = server.accept()
        print(f"Connection from {address} has been established!")

        proper_login = False

        client.send(
            str(
                len(
                    localPublicKey.public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.PKCS1,
                    )
                )
            )
            .zfill(header)
            .encode("utf-8")
        )
        client.send(
            localPublicKey.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.PKCS1,
            )
        )

        message_length = client.recv(header).decode("utf-8")
        try:
            clientPublicKey = client.recv(int(message_length))
            clientPublicKey = serialization.load_der_public_key(
                clientPublicKey, backend=default_backend()
            )
        except Exception as e:
            client.close()
            print(e)
            return
        print(clientPublicKey)

        send_string_to_client(client, build, clientPublicKey)

        send_string_to_client(client, "LOGIN|REQUEST", clientPublicKey)
        recieved_string = recieve_string_from_client(client)
        if recieved_string == "error":
            client.close()
            return
        if recieved_string.startswith("USERNAME|"):
            username = recieved_string[9:]
        recieved_string = recieve_string_from_client(client)
        if recieved_string == "error":
            client.close()
            return
        if recieved_string.startswith("PASSWORD|"):
            password = recieved_string[9:]

        account_id = 0
        proper_login = False

        account_login = {"username": username, "password": password}

        print(account_login)
        print(accounts)

        if account_login in accounts:
            account_id = accounts.index(account_login)
            if accounts_with_client_data[account_id]["client"] != None:
                send_string_to_client(
                    client, "LOGIN|ALREADY_LOGGED_IN", clientPublicKey
                )
                client.close()
                return
            else:
                proper_login = True

        if proper_login:
            send_string_to_client(client, "LOGIN|SUCCESS", clientPublicKey)
            accounts_with_client_data[account_id]["client"] = client
            accounts_with_client_data[account_id]["public_key"] = clientPublicKey
            broadcast(f"LOG | {username} joined the chat.")
            threading.Thread(target=handle, args=(client, username)).start()
        else:
            send_string_to_client(client, "LOGIN|REJECTED", clientPublicKey)
            client.close()
            return

        if proper_login:
            account_login = accounts_with_client_data[account_id]
            try:
                thread = threading.Thread(target=handle, args=[account_login])
                thread.start()
            except:
                pass

    while True:
        client()


recieve()
