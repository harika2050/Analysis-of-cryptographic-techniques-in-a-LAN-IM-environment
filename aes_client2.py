import socket
import select
import errno
import sys
import base64
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2
import time
from time import perf_counter_ns 
import os
import hashlib


BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def get_private_key(password):
    salt = b"this is a salt"
    kdf = PBKDF2(password, salt, 24, 1000)
    key = kdf[:32]
    return key
@profile
def encrypt(raw, password):
    st= time.time()
    private_key = get_private_key(password)
    et= time.time()
    print("Key generation time:", et-st)
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))
@profile
def decrypt(enc, password):
    private_key = get_private_key(password)
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))

    
# First let us encrypt secret message

password = "This passphrase is text."
HEADER_LENGTH = 10

IP = "127.0.0.1"
port = 1234
my_username = input("Enter Username")
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((IP, port))
client_socket.setblocking(False)
username = my_username.encode('utf-8')
username_header = f"{len(username):<{HEADER_LENGTH}}".encode('utf-8')
client_socket.send(username_header + username)
while True:
    ans= input("Do you want to send a file? [Y/N]")
    s=""
    if(ans=="Y"):
        filename= input("enter file name")
        f = open(filename,'rb')
        l = f.read()
        f.close()
        st= time.time()
        encrypted = encrypt(str(l), password)
        et= time.time()
        print("ENnryption time", et-st)
        message_header = f"{len(encrypted):<{HEADER_LENGTH}}".encode('utf-8')
        client_socket.send(message_header+ encrypted)
    else:
        message = input(f"{my_username} >")
        if message:
            st1= time.time()
            encrypted = encrypt(str(message), password)
            et1= time.time()
            print("ENcryption time", et1-st1)
            message_header = f"{len(encrypted):<{HEADER_LENGTH}}".encode('utf-8')
           
            client_socket.send(message_header +encrypted)
        try:  # attempting to receive
            while True:
                username_header = client_socket.recv(HEADER_LENGTH)
                if not len(username_header):
                    print("Connection closed by the server")
                    sys.exit()
                username_length = int(username_header.decode('utf-8').strip())
                username = client_socket.recv(username_length).decode('utf-8')                    
                message_header = client_socket.recv(HEADER_LENGTH)
            #message_header=decrypted[HEADER_LENGTH]
                message_length = int(message_header.decode('utf-8').strip())
            #message= decrypted[message_length]
                message = client_socket.recv(message_length)
                st2= time.time()
                decrypted = decrypt(message, password)
                et2= time.time()
                print("Decryption time", et2-st2)
                print(f"{username}:{decrypted}")
                print(f"{username}:File received")       
        except IOError as e:
            if (e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK):
                print("Reading error")
                sys.exit()
            continue
        except Exception as e:
            print("general error")
            sys.exit()


            
               

