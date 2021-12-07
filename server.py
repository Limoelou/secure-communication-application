import socket
import base64
import secrets
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import scrypt

HOST = "127.0.0.1"
PORT = 60000

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

#Dictionary users / hashes of the passwords
dict = {'Openluminus':'2c38b20740d3abb9142113ee6a206bd1c379f6389b4eca9e7f1cd352cd299176',
'amraji':'f02b405bc0803997674a3b27512273336fdce54dec6dbe92c62b3b8b28d781a7',
'Leviath':'c811df0e0133c4b0b577649864fb71ea2b0e2b8ec3bf23391ad3865084ba5584'}

def connect(server):
    connection, client_address = server.accept()
    return connection, client_address

def verify_username(user):
    return user in dict

def check_password(password_hash, guessed_password):
    try:
        scrypt.decrypt(password_hash, guessed_password)
    except:


def create_session_key():

if __name__ == "__main__":
    server.bind((HOST, PORT))
    server.listen(0)

    while True:
        connection, client_address = connect(server)
        while True:
            user = connection.recv(1024).decode('utf-8')
            if (verify_username(user)):
                print("Auth Successful")
                #on récupère le mdp associé à l'utilisateur
                password_hash = dict[user]
                #generation du sel
                salt = secrets.token_hex(8)
                connection.send(salt.encode('utf-8'))
                #génération de clé de chiffrement (scrypt ?)
                #
                #si on reçoit un nouveau message, on dérive la clé de chiffrement pour générer une nouvelle clé de session  
            else:
                print("Authentication failed")
                connection.send("Connection refused, try again")
                connection.close()

