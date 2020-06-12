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
from memory_profiler import profile

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]
@profile
def encrypt_blob(blob, public_key):
    #Import the Public Key and use for encryption using PKCS1_OAEP
    rsa_key = RSA.importKey(public_key)
    rsa_key = PKCS1_OAEP.new(rsa_key)
    #In determining the chunk size, determine the private key length used in bytes
    #and subtract 42 bytes (when using PKCS1_OAEP). The data will be in encrypted
    #in chunks
    chunk_size = 50
    offset = 0
    end_loop = False
    encrypted =  ""
    while not end_loop:
        #The chunk
        chunk = blob[offset:offset + chunk_size]
        #If the data chunk is less then the chunk size, then we need to add
        #padding with " ". This indicates the we reached the end of the file
        #so we end loop here
        if len(chunk) % chunk_size != 0:
            end_loop = True
            chunk += (" " * (chunk_size - len(chunk))).encode()
        #Append the encrypted chunk to the overall encrypted file
        encrypted += str(rsa_key.encrypt(chunk))
        #Increase the offset by chunk size
        offset += chunk_size
    #Base 64 encode the encrypted file
    encrypted= encrypted.encode()
    return base64.b64encode(encrypted)
def decrypt_blob(encrypted_blob, private_key):
    #Import the Private Key and use for decryption using PKCS1_OAEP
    rsakey = RSA.importKey(private_key)
    rsakey = PKCS1_OAEP.new(rsakey)
    #Base 64 decode the data
    encrypted_blob = base64.b64decode(encrypted_blob)
    #encrypted_blob= encrypted_blob.decode()
    #In determining the chunk size, determine the private key length used in bytes.
    #The data will be in decrypted in chunks
    chunk_size = 50
    offset = 0
    decrypted = ""
    chunk=""
    #keep loop going as long as we have chunks to decrypt
    while offset < len(encrypted_blob):
        #The chunk
        chunk = encrypted_blob[offset: offset + chunk_size]
        
        #Append the decrypted chunk to the overall decrypted file
        decrypted += rsakey.decrypt(chunk)

        #Increase the offset by chunk size
        offset += chunk_size

    #return the decompressed decrypted data
    return (decrypted)
# First let us encrypt secret message

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
st1= time.time()
new_key = RSA.generate(4096, e=65537)
et1= time.time()
print("The key generation time is", et1- st1)
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



