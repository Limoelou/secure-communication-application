import socket
import ssl
from Crypto.Hash import SHA256

HOST = "127.0.0.1"
PORT = 60000

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server = ssl.wrap_socket(
    server, server_side=True, keyfile="./private-key.pem", certfile="./cert.pem"
)

def connect(server):
    connection, client_address = server.accept()
    return connection, client_address

def auth(connection):
    # passwd est le digest de "Pancake_To_the_moon"
    passwd = "209cd49c43e010afb5cfef36bb48091b371e2f5f86e078079c5b51baa9ba6a2b"
    data = connection.recv(1024)
    hash = SHA256.new()
    hash.update(data)
    return hash.hexdigest() == passwd

if __name__ == "__main__":
    server.bind((HOST, PORT))
    server.listen(0)

    while True:
        connection, client_address = connect(server)
        while True:
            if (auth(connection)):
                print("Auth Successful")
            else:
                print("Auth failed")
                connection.close()
            data = connection.recv(1024)
            if not data:
                break
            print(f"Received: {data.decode('utf-8')}")
