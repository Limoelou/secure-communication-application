import socket
from base64 import b64encode, b64decode
import secrets
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import scrypt, HKDF
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256

counter = 0

def xb(ba1, ba2):
    return bytes([_a ^ _b for (_a, _b) in zip(ba1, ba2)])


def connect(server):
    connection, client_address = server.accept()
    return connection, client_address


def deriv_key(password, salt):
    #return scrypt(password, salt, session_key_len*3, N=2**14, r=block_size, p=1)
    return HKDF(password, 32, salt, SHA256, 3)


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
    cipher_msg = aes.encrypt(pad(msg, AES.block_size, style="pkcs7"))

    return b64encode(iv + cipher_msg)


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


def decrypt(key, ciphertext, tag):
    global counter
    msg = b""
    try:
        nonce = HKDF(xb(key, counter.to_bytes(12, 'big')), 12, salt, SHA256, 1)
        aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
        msg = aes.decrypt_and_verify(ciphertext, tag)
        counter += 1
    except Exception as e:
        print(e, "Incorrect decryption")
    return msg


if __name__ == "__main__":
    HOST = "127.0.0.1"
    PORT = 60000
    session_key_len = 32
    block_size = 8
    counter = 0
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    dict = {'Openluminus': b'31f7a65e315586ac198bd798b6629ce4903d0899476d5741a9f32e2e521b6a66',
            'amraji': b'f02b405bc0803997674a3b27512273336fdce54dec6dbe92c62b3b8b28d781a7',
            'Leviath': b'c811df0e0133c4b0b577649864fb71ea2b0e2b8ec3bf23391ad3865084ba5584'}

    server.bind((HOST, PORT))
    server.listen(0)

    while True:
        connection, client_address = connect(server)
        while True:
            user = connection.recv(1024).decode('utf-8')
            if (verify_username(user)):
                salt = secrets.token_hex(8).encode()
                print("saaaalt", type(salt))
                connection.send(salt)

                password = dict[user]

                key1, key2, key3 = deriv_key(password, salt)

                challenge1 = connection.recv(1024)

                ch1_hash = challenge_decrypt(key1, challenge1)

                if hash_verify(ch1_hash, password):
                    print("challenge 1 - ok")
                else:
                    print("challenge 1 - failed")
                    connection.close()
                
                challenge2 = challenge_encrypt(key2, password)
                connection.send(challenge2)

                msg_enc = connection.recv(1024)

                tag = connection.recv(1024)

                msg_dec = decrypt(key3, msg_enc, tag)

                print(msg_dec)

                # second message

                msg_enc = connection.recv(1024)
                
                tag = connection.recv(1024)

                msg_dec = decrypt(key3, msg_enc, tag)
                print(msg_dec)

            else:
                connection.send(b"Connection refused, try again")
                connection.close()
