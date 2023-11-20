import select
import socket
import time
import threading

PORT = int(input("Enter port: "))
IP_ADDRESS = "127.0.0.1"
receiver_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
receiver_sock.bind((IP_ADDRESS, PORT))
TIMEOUT = 16


def establish_connection():
    established = False
    while not established:
        data, address = receiver_sock.recvfrom(1024)
        message = data.decode()
        if message[0] == '1':
            print(f"Received message from {address}: message type 1 - connect")
            receiver_sock.sendto("3".encode(), address)
            print(f"Sent message to {address}: message type 3 - acknowledgement")
            established = True
        time.sleep(1)


def receive():
    while True:
        data, address = receiver_sock.recvfrom(1024)
        message = data.decode()
        if message[0] == '0':
            print(f"Received message from {address}: message type 0 - keep alive")
            receiver_sock.sendto("3".encode(), address)
            print(f"Sent message to {address}: message type 3 - acknowledgement")
        elif message[0] == '2':
            print(f"Received message from {address}: message type 2 - message send request")
            receiver_sock.sendto("3".encode(), address)
            print(f"Sent message to {address}: message type 3 - acknowledgement ")
            receive_message()
        elif message[0] == '5':
            print(f"Received message from {address}: message type 5 - file send request")
            receiver_sock.sendto("3".encode(), address)
            print(f"Sent message to {address}: message type 3 - acknowledgement ")
            receive_file()
        elif message[0] == '7':
            print(f"Received message from {address}: message type 7 - connection close request")
            receiver_sock.sendto("3".encode(), address)
            print(f"Sent message to {address}: message type 3 - acknowledgement ")
            print("Connection closed.")
            break


def receive_file():
    pass


def receive_message():
    while True:
        data, address = receiver_sock.recvfrom(1024)
        message = data.decode()
        if message[0] == '4':
            print(f"Received message from {address}: message type 4 - message")
            print(f"Message: {message[1:]}")
            receiver_sock.sendto("3".encode(), address)
            print(f"Sent message to {address}: message type 3 - acknowledgement")
            break




# def comm_upkeep(connection_close_event, message_request_event):
#     start_time = time.time()
#     while not connection_close_event.is_set() and not message_request_event.is_set():
#         elapsed_time = time.time() - start_time
#         if elapsed_time >= TIMEOUT:
#             print(f"Timeout reached. Connection closed due to timeout.")
#             connection_close_event.set()
#         timeout = max(0, int(TIMEOUT - elapsed_time))
#         ready_packets, _, _ = select.select([receiver_sock], [], [], timeout)
#         if ready_packets:
#             data, address = receiver_sock.recvfrom(1024)
#             message = data.decode()
#             if message[0] == '0':
#                 print(f"Received message from {address}: message type 0 - keep alive")
#                 start_time = time.time()
#                 receiver_sock.sendto("3".encode(), address)
#                 print(f"Sent message to {address}: message type 3 - acknowledgement")
#             elif message[0] == '2':
#                 print(f"Received message from {address}: message type 2 - message send request")
#                 receiver_sock.sendto("3".encode(), address)
#                 print(f"Sent message to {address}: message type 3 - acknowledgement ")
#                 message_request_event.set()
#                 receive_message(message_request_event)


def start():
    establish_connection()
    receive()
    # while True:
    #     output = receive_message()
    #     if output == -1:
    #         break
    # connection_closed_event = threading.Event()
    # message_request_event = threading.Event()
    # comm_upkeep_thread = threading.Thread(target=comm_upkeep, args=(connection_closed_event, message_request_event))
    # comm_upkeep_thread.start()


start()
