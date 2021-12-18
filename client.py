import socket
from time import sleep
from Crypto.Protocol.KDF import scrypt, HKDF
from Crypto.Cipher import AES
import hashlib
from Crypto.Util.Padding import pad, unpad
import secrets
from base64 import b64decode, b64encode
from Crypto.Hash import SHA256
import time

counter = 0

def xb(ba1, ba2):
    return bytes([_a ^ _b for (_a, _b) in zip(ba1, ba2)])

def connect(client):
    client.connect((SERVER_HOST, SERVER_PORT))


def auth(client):
    # print("Enter username : ")
    USER = "Openluminus"
    client.send(USER.encode('utf-8'))

def deriv_key(password, salt):
    #return scrypt(pwd, salt, session_key_len*3, N=2**14, r=block_size, p=1)
    return HKDF(password, 32, salt, SHA256, 3)


def key_split(key, key_len):
    return key[0:key_len], key[key_len: key_len * 2], key[key_len * 2:]


def hash_verify(decrypted, expected):
    return decrypted == expected


def challenge_encrypt(key, msg):
    iv = secrets.token_bytes(16)
    aes = AES.new(key, AES.MODE_CBC, iv)
    cipher_msg = aes.encrypt(pad(msg, AES.block_size, style="pkcs7"))
    return b64encode(iv + cipher_msg)

def generate_nonce(base_nonce, counter):
    #Incrementing with counter to avoid using the same twice
    coef = counter.to_bytes(12, 'big')
    return bytes([a ^ b for a, b in zip(base_nonce, coef)])

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
    global counter
    nonce = HKDF(xb(key, counter.to_bytes(12, 'big')), 12, salt, SHA256, 1)
    aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = aes.encrypt_and_digest(msg)
    counter += 1
    return ciphertext, tag


if __name__ == "__main__":
    HOST = "127.0.0.1"
    #PORT = 60002
    SERVER_HOST = "127.0.0.1"
    SERVER_PORT = 60000
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    session_key_len = 32
    block_size = 8
    connect(connection)
    auth(connection)

    while True:
        salt = connection.recv(1024)
        password = "toto"
        password_hash = hashlib.sha256(password.encode()).hexdigest().encode()

        key1, key2, key3 = deriv_key(password_hash, salt)

        challenge1 = challenge_encrypt(key1, password_hash)

        connection.send(challenge1)

        challenge2 = connection.recv(1024)
        # print("challenge 2", type(challenge2), challenge2)
        ch2_hash = challenge_decrypt(key2, challenge2)

        if hash_verify(ch2_hash, password_hash):
            print("challenge 2 - ok")
        else:
            print("challenge 2 - failed")
            connection.close()

        msg_enc, tag = encrypt(key3, b"Let's sleep for a while")

        connection.send(msg_enc)
        connection.send(tag)

        msg_enc, tag = encrypt(key3, b"another message")
        connection.send(msg_enc)

        time.sleep(1)
        connection.send(tag)
        print("The end")
        sleep(1)
