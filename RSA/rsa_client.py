import socket
import select
import errno
import sys
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2
import time
from time import perf_counter_ns 
import os
import hashlib

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def encrypt_blob(blob, public_key):
    rsa_key = RSA.importKey(public_key)
    rsa_key = PKCS1_OAEP.new(rsa_key)
    chunk_size = 50
    offset = 0
    end_loop = False
    encrypted =  ""
    while not end_loop:
        chunk = blob[offset:offset + chunk_size]        
        if len(chunk) % chunk_size != 0:
            end_loop = True
            chunk += (" " * (chunk_size - len(chunk))).encode()
        
        encrypted += str(rsa_key.encrypt(chunk))
        offset += chunk_size
    encrypted= encrypted.encode()
    return base64.b64encode(encrypted)
    
    
def decrypt_blob(encrypted_blob, private_key):
    rsakey = RSA.importKey(private_key)
    rsakey = PKCS1_OAEP.new(rsakey)
    encrypted_blob = base64.b64decode(encrypted_blob)
    chunk_size = 50
    offset = 0
    decrypted = ""
    chunk=""
    while offset < len(encrypted_blob):      
        chunk = encrypted_blob[offset: offset + chunk_size]
        decrypted += rsakey.decrypt(chunk)
        offset += chunk_size
    return (decrypted)
    
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

new_key = RSA.generate(4096, e=65537)
#The private key in PEM format
private_key = new_key.exportKey("PEM")
#The public key in PEM Format
public_key = new_key.publickey().exportKey("PEM")

while True:
    ans= input("Do you want to send a file? [Y/N]")
    s=""
    if(ans=="Y"):
        filename= input("enter file name")
        f = open(filename,'rb')
        l = f.read()              
        start_time= time.time()
        encrypted = encrypt_blob(l, public_key)
        print("File encryption time", (time.time()-start_time))
        message_header = f"{len(encrypted):<{HEADER_LENGTH}}".encode('utf-8')
        client_socket.send(message_header+ encrypted)
    else:
    
        message = input(f"{my_username} >")
    # message=""
        if message:
        #message = message.encode('utf-8')
        # HERE THE ACTUAL ENCRYPTION SHOULD TAKE PLACE
            start1= time.time()
            encrypted = encrypt_blob(str(message,public_key))
            end1= time.time()
            print("Message encryption time", end1-start1)
            message_header = f"{len(encrypted):<{HEADER_LENGTH}}".encode('utf-8')
           # message_type= "n".encode('utf-8')
            client_socket.send(message_header + encrypted)
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
                #st1= time.time()
                decrypted = decrypt_blob(message, private_key)  
                
                #print("Decryption time:  " ,time.time()-st1)
               
                print(decrypted)
                print(f"{username}:>File received")
                
        except IOError as e:
            if (e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK):
                print("Reading error")
                sys.exit()
            continue
        except Exception as e:
            print("general error")
            sys.exit()



