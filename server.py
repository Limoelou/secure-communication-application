import socket
from base64 import b64encode, b64decode
import secrets
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import scrypt

HOST = "127.0.0.1"
PORT = 60000

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
    # aes = AES
    iv = b64encode(secrets.token_bytes(16))
    aes = AES.new(key, AES.MODE_CBC, iv)
    cipher_msg = b64encode(aes.encrypt(msg))
    return iv + cipher_msg


def challenge_decrypt(key, cipher_text):
    try:
        cipher_text = b64decode(cipher_text)

        iv = cipher_text[:32]
        decrypt_msg = b64decode(cipher_text[32:])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        msg = cipher.decrypt(decrypt_msg)
    except Exception as e:
        print("Incorrect decryption")
    return msg


def encrypt(key, msg):
    global counter
    #nonce = counter ...
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(msg)
    encrypt_list = [b64encode(x).decode('utf-8') for x in [cipher.nonce, ciphertext, tag]]
    counter += 1
    return encrypt_list


def decrypt(encrypt_list, key):
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=encrypt_list[0].b64decode())
        msg = cipher.decrypt_and_verify(encrypt_list[1].b64decode(), encrypt_list[2].b64decode())
    except Exception as e:
        print("Incorrect decryption")
    return msg
#def create_session_key():


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
                password_hash = hashlib.sha256(dict[user].encode())
        
                # generate the first session key from the hash of the password
                session_key = deriv_key(password_hash, salt) #scrypt(password_hash, salt_from_server, session_key_len * 3, N=2**14, r=block_size, p=1)
        
                # separate the key into 3 equals parts : one is the challenge for the client, the second one is for the server, and the last one is the final session key used.
                key1, key2, key3 = key_split(session_key, session_key_len*3)
        
                # le client envoie le challenge au serveur :
                client.send(challenge_encrypt(key1, password_hash.hexdigest()))
        
                #si on reçoit un nouveau message, on dérive la clé de chiffrement pour générer une nouvelle clé de session  
            else:
                print("Authentication failed")
                connection.send("Connection refused, try again")
                connection.close()

