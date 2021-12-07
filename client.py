import socket
from time import sleep
from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import AES
import hashlib
import secrets
import pyaes
from base64 import b64decode, b64encode
HOST = "127.0.0.1"
PORT = 60002

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 60000

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

#length for the AES key generated
session_key_len = 256

#block size for the key generated
block_size = 8


def connect(client):
    client.connect((SERVER_HOST, SERVER_PORT))

def auth(client):
    print("Enter username : ")
    USER = input()
    client.send(USER.encode('utf-8'))
    #if(client.recv(4096 == ))

def deriv_key(pwd, salt):
    return scrypt(pwd, salt, session_key_len*3, N=2**14, r=block_size, p=1)

def key_split(key, key_len):
    return key[0:key_len], key[key_len: key_len * 2], key[key_len * 2:]

def hash_verify(h):
    
def challenge_encrypt(AES_key, msg):
    cipher1 = AES
    cipher = AES.new(key, AES.MODE_CTR)
    cipher_msg = cipher.encrypt(msg)
    encrypt_nonce = b64encode(cipher.nonce)
    return cipher_msg, encrypt_nonce

def challenge_decrypt(cipher_msg, AES_key):
    try:
        decrypt_nonce = b64decode(encrypt_nonce)
        decrypt_msg = b64decode(cipher_msg)
        cipher = AES.new(key, AES.MODE_CTR, nonce=decrypt_nonce)
        msg = cipher.decrypt(decrypt_msg)
    except Exception as e:
        print("Incorrect decryption")
    return msg
  
def encrypt(key, msg):
    cipher = AES.new(key, AES.MODE_CTR)
    cipher_msg = cipher.encrypt(msg)
    encrypt_nonce = b64encode(cipher.nonce)
    return cipher_msg, encrypt_nonce

def decrypt(cipher_msg, encrypt_nonce, key):
    try:
        decrypt_nonce = b64decode(encrypt_nonce)
        decrypt_msg = b64decode(cipher_msg)
        cipher = AES.new(key, AES.MODE_CTR, nonce=decrypt_nonce)
        msg = cipher.decrypt(decrypt_msg)
    except Exception as e:
        print("Incorrect decryption")
    return msg

def pyaes_encrypt(password_hash, key):
   
    aes = pyaes.AES(key.encode('utf-8'))
    res = aes.encrypt(password_hash)
    return res.join("%02x"%x for x in res)

def pyaes_decrypt(cipher, key):
    
    aes = pyaes.AES(key.encode('utf-8'))
    chunks = [cipher[i:i+2] for i in range(0, len(cipher), 2)]
    array = [int(x, 16) for x in chunks]
    return aes.decrypt(array)

if __name__ == "__main__":
    connect(client)
    auth(client)
    print("done")
    while True:
        salt_from_server = client.recv(4096).decode('utf-8')
        print(salt_from_server)

        print("Enter password : ")
        password = input()
        
        #hash the password
        password_hash = hashlib.sha256(password.encode())
        
        #generate the first session key from the hash of the password
        session_key = deriv_key(password_hash, salt_from_server) #scrypt(password_hash, salt_from_server, session_key_len * 3, N=2**14, r=block_size, p=1)
        
        #separate the key into 3 equals parts : one is the challenge for the client, the second one is for the server, and the last one is the final session key used.
        key1, key2, key3 = key_split(session_key, session_key_len*3)
        
        #le client envoie le challenge au serveur :
        client.send(challenge_encrypt(key1, password_hash.hexdigest()))
        
        #le client reçoit le challenge du serveur :
        challenge = client.recv(1024)
        
        #il déchiffre le
        decrypted = challenge_decrypt(challenge)
        
        #verify que le hash obtenu correspond au hash du mdp
        hash_verify(challenge):
            
     
        
        
        #accept connexion ?
        sleep(1)