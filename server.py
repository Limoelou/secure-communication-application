import socket
from base64 import b64encode, b64decode
import secrets
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import scrypt
import hashlib

HOST = "127.0.0.1"
PORT = 60000
session_key_len = 256
block_size = 8
counter = 0

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

#Dictionary users / hashes of the passwords
dict = {'Openluminus':'2c38b20740d3abb9142113ee6a206bd1c379f6389b4eca9e7f1cd352cd299176',
'amraji':'f02b405bc0803997674a3b27512273336fdce54dec6dbe92c62b3b8b28d781a7',
'Leviath':'c811df0e0133c4b0b577649864fb71ea2b0e2b8ec3bf23391ad3865084ba5584'}


def connect(server):
    connection, client_address = server.accept()
    return connection, client_address


def deriv_key(pwd, salt):
    return scrypt(pwd, salt, session_key_len*3, N=2**14, r=block_size, p=1)


def key_split(key, key_len):
    return key[0:key_len], key[key_len: key_len * 2], key[key_len * 2:]


def hash_verify(decrypted, expected):
    return decrypted == expected


def verify_username(user):
    return user in dict


def check_password(password_hash, guessed_password):
    try:
        scrypt.decrypt(password_hash, guessed_password)
    except:
        print('erreur')


def challenge_encrypt(key, msg):
    iv = secrets.token_bytes(16)
    aes = AES.new(key, AES.MODE_CBC, iv)
    cipher_msg = aes.encrypt(pad(msg, AES.block_size))
    output = b64encode(iv + cipher_msg)  # .decode('utf-8')
    return output


def challenge_decrypt(key, rcv_msg):
    msg = ""
    try:
        decoded = b64decode(rcv_msg)
        iv = decoded[:16]
        cipher_text = decoded[16:]
        aes = AES.new(key, AES.MODE_CBC, iv)
        msg = aes.decrypt(cipher_text)
        msg = unpad(msg, AES.block_size, style="pkcs7")
    except Exception as e:
        print(e, "Incorrect decryption")
    return msg


def encrypt(key, msg):
    aes = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = aes.encrypt_and_digest(msg)
    encrypt_list = [b64encode(x) for x in [aes.nonce, ciphertext, tag]]
    return encrypt_list


def decrypt(encrypt_list: list, key):
    msg = b""
    try:
        aes = AES.new(key, AES.MODE_GCM, nonce=b64decode(encrypt_list[0]))
        msg = aes.decrypt_and_verify(
            b64decode(encrypt_list[1]), b64decode(encrypt_list[2]))
    except Exception as e:
        print(e, "Incorrect decryption")
    return msg


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
                print("pass serv :", password_hash)
                
                #generation du sel
                salt = secrets.token_hex(8)
                print("salt from server:", salt)
                connection.send(salt.encode('utf-8'))
                #génération de clé de chiffrement (scrypt ?)
                password_hash = hashlib.sha256(dict[user].encode())
                digest = password_hash.hexdigest()
                print("password hash ?:", digest)
                # generate the first session key from the hash of the password
                session_key = deriv_key(digest, salt) #scrypt(password_hash, salt_from_server, session_key_len * 3, N=2**14, r=block_size, p=1)
                print("session key : ", session_key)
                # separate the key into 3 equals parts : one is the challenge for the client, the second one is for the server, and the last one is the final session key used.
                key1, key2, key3 = key_split(session_key, session_key_len)
                print("key1 : ", key1)
                print("key2 : ", key2)
                print("key3 : ", key3)
            
                challenge_client = connection.recv(1024).decode()

                print("challenge client : ", challenge_client)

                print(challenge_decrypt(key1, challenge_client))
                if challenge_decrypt(key1, challenge_client) == digest:
                        print("sa fionctojnaaa")
                else:
                    print("sa fonssionn po")
                # le serveur envoie le challenge au client :
                """
                connection.send(challenge_encrypt(key2, password_hash.hexdigest()))
        
                #si on reçoit un nouveau message, on dérive la clé de chiffrement pour générer une nouvelle clé de session  
            else:
                print("Authentication failed")
                connection.send("Connection refused, try again")
                connection.close()
                """
