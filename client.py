import socket
import threading
import time
import os
import inspect
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from hybrid_rsa_aes import HybridCipher
import win32gui
from getpass import getpass
from ctypes import c_long, c_ulong, windll

build = "2.2 Secure"

os.system(f"title Chat Application by SleepyStew (v{build})")

src_file_path = inspect.getfile(lambda: None)

console = []

print("Generating keypair...")

localPrivateKey = rsa.generate_private_key(
    public_exponent=65537, key_size=1024, backend=default_backend()
)
localPublicKey = localPrivateKey.public_key()

serverPublicKey = None

header = 64
host = "pythonchat.doublemc.live"
port = 30012

valid_login = False

username = ""
password = ""

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((host, port))

handle = windll.kernel32.GetStdHandle(c_long(-11))
hwnd = win32gui.GetForegroundWindow()

send_thread = None


def resetcursor():
    global send_thread
    value = 0 + (0 << 16)
    windll.kernel32.SetConsoleCursorPosition(handle, c_ulong(value))
    for line in console:
        print(line)
    if send_thread == "Start":
        send_thread = StoppableThread(target=send)
        send_thread.start()
    elif send_thread != None:
        send_thread.stop()
        send_thread = StoppableThread(target=send)
        send_thread.start()


def log_to_console(message):
    console.append(message)
    resetcursor()


def rest():
    os._exit(0)


class StoppableThread(threading.Thread):
    """Thread class with a stop() method. The thread itself has to check
    regularly for the stopped() condition."""

    def __init__(self, *args, **kwargs):
        super(StoppableThread, self).__init__(*args, **kwargs)
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def stopped(self):
        return self._stop_event.is_set()


def encrypt(message):
    encrypted_message = (
        HybridCipher()
        .encrypt(data=message, rsa_public_key=serverPublicKey)
        .encode("utf-8")
    )
    return encrypted_message


def decrypt(encrypted_message):
    decrypted_message = HybridCipher().decrypt(
        cipher_text=encrypted_message.decode("utf-8"), rsa_private_key=localPrivateKey
    )
    return decrypted_message


def send_message_to_server(message):
    try:
        message = "MESSAGE|" + message
        client.send(str(len(encrypt(message))).zfill(header).encode("utf-8"))
        client.send(encrypt(message))
    except Exception as e:
        print(e)
        return "error"


def send_string_to_server(message):
    try:
        client.send(str(len(encrypt(message))).zfill(header).encode("utf-8"))
        client.send(encrypt(message))
    except Exception as e:
        print(e)
        return "error"


def recieve_from_server():
    message_length = client.recv(header).decode("utf-8")
    recieved_message = decrypt(client.recv(int(message_length)))
    return recieved_message


def recieve():
    global serverPublicKey
    print("Exchanging keys...")
    message_length = client.recv(header).decode("utf-8")
    serverPublicKey = client.recv(int(message_length))
    serverPublicKey = serialization.load_der_public_key(
        serverPublicKey, backend=default_backend()
    )
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
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.PKCS1
        )
    )
    print("Successfully made a secure connection with the server.")
    print("Checking version...")
    latest_version = recieve_from_server()
    if latest_version == build:
        print(f"You are running the latest version. (v{build})")
    else:
        print(
            "You are running an outdated version. Please update to the latest version."
        )
        input()
        os.exit()
    print("")
    print("       Login to your account")
    print("-----------------------------------")
    request_credentials()
    while True:
        global valid_login, send_thread

        message = recieve_from_server()

        # Global Prefix List

        if message.startswith("MESSAGE|"):
            if valid_login == True:
                if message[8:].startswith(username):
                    log_to_console(message[8:])
                else:
                    log_to_console(message[8:])

        if message.startswith("LOGIN|REQUEST"):
            send_string_to_server("USERNAME|" + username)
            send_string_to_server("PASSWORD|" + password)
            response = recieve_from_server()
            if response == "LOGIN|SUCCESS":
                os.system("cls")
                log_to_console("Login Successful | Welcome to the chat!")
                valid_login = True
                send_thread = "Start"
                continue
            elif response == "LOGIN|REJECTED":
                os.system("cls")
                log_to_console("Incorrect username or password")
                time.sleep(5)
                recieve_thread.stop()
                rest()
            elif response == "LOGIN|ALREADY_LOGGED_IN":
                os.system("cls")
                log_to_console("This account is already logged in")
                time.sleep(5)
                recieve_thread.stop()
                rest()
            else:
                log_to_console("An error occured, try restarting the program.")


def send():
    time.sleep(0.05)
    stdin = open(0)
    print("> ", end="", flush=1)
    message = stdin.readline().strip()
    if not message.isspace() and not message == "":
        send_message_to_server(message)
    else:
        resetcursor()


def request_credentials():
    global username, password
    username = input("Enter your username: ")
    password = getpass("Enter your password: ")


recieve_thread = StoppableThread(target=recieve)
recieve_thread.start()
