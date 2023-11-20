import select
import socket
import threading
import time

DST_PORT = int(input("Enter port: "))
DST_IP_ADDRESS = input("Enter IP address: ")
DESTINATION = (DST_IP_ADDRESS, DST_PORT)
FORMAT = 'utf-8'
sender_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
TIMEOUT = 16


def establish_connection():
    established = False
    while not established:
        sender_sock.send("1".encode(FORMAT))
        print(f"Sent message to {DESTINATION}: message type 1 - connect")
        data, address = sender_sock.recvfrom(1024)
        message = data.decode()
        if message[0] == '3':
            print(f"Received message from {address}: message type 3 - acknowledgement")
            print("Connection established.")
            established = True
        time.sleep(1)


def comm_upkeep(connection_close_event, message_request_event):
    start_time = time.time()
    while not connection_close_event.is_set():
        elapsed_time = time.time() - start_time
        if elapsed_time >= TIMEOUT:
            print(f"Timeout reached. Connection closed due to timeout.")
            connection_close_event.set()
        sender_sock.send("0".encode(FORMAT))
        print(f"Sent message to {DESTINATION}: message type 0 - keep alive")
        timeout = max(0, int(TIMEOUT - elapsed_time))
        ready_packets, _, _ = select.select([sender_sock], [], [], timeout)
        if ready_packets:
            data, address = sender_sock.recvfrom(1024)
            message = data.decode()
            if message[0] == '3':
                start_time = time.time()
                print(f"Received message from {address}: message type 3 - acknowledgement")
            else:
                print("Connection closed due to timeout.")
                connection_close_event.set()
        time.sleep(5)


def user_input(connection_close_event, message_request_event):
    print("If you want to send a message, type 'message'.")
    print("If you want to send a file, type 'file'.")
    print("If you want to close the connection, type 'close'.")
    while True:
        choice = input()
        if choice == 'message':
            message_request_event.set()
            user_message = "4" + input("Enter your message:")
            sender_sock.send("2".encode(FORMAT))
            print(f"Sent message to {DESTINATION}: message type 2 - message send request")
            acknowledged = False
            while not acknowledged:
                data, address = sender_sock.recvfrom(1024)
                message = data.decode()
                if message[0] == '3':
                    print(f"Received message from {address}: message type 3 - acknowledgement")
                    acknowledged = True
            sender_sock.send(user_message.encode(FORMAT))
            print(f"Sent message to {DESTINATION}: message type 4 - message")
            message_request_event.clear()
        elif choice == 'file':
            message_request_event.set()
            print("Enter the path to the file:")
            path = input()
            with open(path, 'rb') as file:
                file_data = file.read(1024)
                while file_data:
                    sender_sock.send(file_data)
                    file_data = file.read(1024)
            print(f"Sent file to {DESTINATION}: message type 2 - data transfer")
        elif choice == 'close':
            connection_close_event.set()
            print("Connection closed.")
            break


def start():
    connection_close_event = threading.Event()
    message_request_event = threading.Event()
    sender_sock.connect((DST_IP_ADDRESS, DST_PORT))
    establish_connection()
    comm_upkeep_thread = threading.Thread(target=comm_upkeep, args=(connection_close_event, message_request_event))
    comm_upkeep_thread.start()
    user_input_thread = threading.Thread(target=user_input, args=(connection_close_event, message_request_event))
    user_input_thread.start()


start()
