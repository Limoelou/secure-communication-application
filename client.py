import socket
import ssl
from time import sleep

HOST = "127.0.0.1"
PORT = 60002

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 60000

PASSWD = "Pancake_To_the_moon"

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

client = ssl.wrap_socket(client, keyfile="./private-key.pem", certfile="./cert.pem")

def connect(client):
    client.bind((HOST, PORT))
    client.connect((SERVER_HOST, SERVER_PORT))

def auth(client):
    client.send(PASSWD.encode('utf-8'))

if __name__ == "__main__":
    connect(client)
    auth(client)
    print("done")
    while True:
        sleep(1)