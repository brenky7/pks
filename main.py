import socket
import threading
import sender
import receiver

choice = input("Choose role (sender/receiver): ")
switch_roles_event = threading.Event()
connection_closed_event = threading.Event()
thread = None
current_role = None
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


if choice == "sender":
    current_role = "sender"
    DST_PORT = int(input("Enter port: "))
    DST_IP_ADDRESS = input("Enter IP address: ")
    DESTINATION = (DST_IP_ADDRESS, DST_PORT)
    sock.connect((DST_IP_ADDRESS, DST_PORT))
    thread = threading.Thread(target=sender.main, args=(switch_roles_event, connection_closed_event, sock, DESTINATION))
elif choice == "receiver":
    PORT = int(input("Enter port: "))
    IP_ADDRESS = "127.0.0.1"
    sock.bind((IP_ADDRESS, PORT))
    current_role = "receiver"
    thread = threading.Thread(target=receiver.main, args=(switch_roles_event, connection_closed_event, sock))
thread.start()
while True:
    if switch_roles_event.is_set():
        thread.join()
        if current_role == "sender":
            current_role = "receiver"
            PORT = int(input("Enter port: "))
            IP_ADDRESS = "127.0.0.1"
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((IP_ADDRESS, PORT))
            thread = threading.Thread(target=receiver.main, args=(switch_roles_event, connection_closed_event, sock))
        elif current_role == "receiver":
            current_role = "sender"
            DST_PORT = int(input("Enter port: "))
            DST_IP_ADDRESS = input("Enter IP address: ")
            DESTINATION = (DST_IP_ADDRESS, DST_PORT)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect((DST_IP_ADDRESS, DST_PORT))
            thread = threading.Thread(target=sender.main, args=(switch_roles_event, connection_closed_event, sock, DESTINATION))
        switch_roles_event.clear()
        thread.start()
    elif connection_closed_event.is_set():
        thread.join()
        break
