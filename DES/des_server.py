import socket
import select #multiple clients
HEADER_LENGTH=10
IP="127.0.0.1"
port=1234
server_socket= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1) #allows me to reconnect
server_socket.bind((IP, port))
server_socket.listen()
sockets_list=[server_socket]
clients={} #client socket will be the key and the data will be the value

#now we are actuallt receiving messages from the clients
def receive_message(client_socket):
    try:
        message_header=client_socket.recv(HEADER_LENGTH)
        if(len(message_header)==0):
            return False
        message_length=int(message_header.decode('utf-8').strip())
        return({"header":message_header, "data":client_socket.recv(message_length)})
    except:
        return False
while True:
    read_sockets, _, exception_sockets= select.select(sockets_list, [], sockets_list)
    for notified_socket in read_sockets:
        if(notified_socket==server_socket): #this is new connection
            client_socket, client_address= server_socket.accept()
            user= receive_message(client_socket)
            if user==False:
                continue
            sockets_list.append(client_socket)
            clients[client_socket]=user
            print(f"Accepted a new connection from {client_address[0]}:{client_address[1]} Username:{user['data'].decode('utf-8')}")
        else:
            message= receive_message(notified_socket)
        # write data to a file
            if message is False: #if any client has disconnected
                print(f"Closed connection from {clients[notified_socket]['data'].decode('utf-8')}")
                sockets_list.remove(notified_socket)
                del clients[notified_socket]
                continue
            user= clients[notified_socket] #is the message has actually some text
            print(f"Received message from {user['data'].decode('utf-8')}: {message['data']}")
            #now we want to print this message across all the clients
            for client_socket in clients:
                if(client_socket!=notified_socket):
                    client_socket.send(user['header']+user['data']+ message['header']+ message['data'])
    for notified_socket in exception_sockets:
        sockets_list.remove(notified_socket)
        del clients[notified_socket]
