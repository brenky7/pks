import os.path
import socket
import struct
import threading
import time
import crcmod
import math


FORMAT = 'utf-8'
RECEIVE_SIZE = 60000
TIMEOUT = 26
WINDOW_SIZE = 4


def establish_connection(sender_sock, DESTINATION):
    established = False
    while not established:
        try:
            while not established:
                sender_sock.send("1".encode(FORMAT))
                print(f"Sent message to {DESTINATION}: message type 1 - connect")
                data, address = sender_sock.recvfrom(RECEIVE_SIZE)
                message = data.decode()
                if message[0] == '2':
                    print(f"Received message from {address}: message type 2 - acknowledgement")
                    print("Connection established.")
                    established = True
                if not established:
                    time.sleep(5)
        except ConnectionRefusedError:
            print("Destination unreachable.")
            time.sleep(5)


def comm_upkeep(sender_sock, DESTINATION, local_conn_close_event, message_request_event, local_switch_event):
    sender_sock.settimeout(TIMEOUT)
    while not local_conn_close_event.is_set() and not message_request_event.is_set() and not local_switch_event.is_set():
        try:
            sender_sock.send("0".encode(FORMAT))
            print(f"Sent message to {DESTINATION}: message type 0 - keep alive")

            data, address = sender_sock.recvfrom(RECEIVE_SIZE)
            message = data.decode()
            if message[0] == '2':
                sender_sock.settimeout(TIMEOUT)
                print(f"Received message from {address}: message type 2 - acknowledgement")
            elif message[0] == '7':
                sender_sock.settimeout(None)
                print(f"Received message from {address}: message type 7 - request to switch roles")
                sender_sock.send("2".encode(FORMAT))
                print(f"Sent message to {address}: message type 2 - acknowledgement to switch")
                local_switch_event.set()
                break
            elif message[0] == '8':
                sender_sock.settimeout(None)
                print(f"Received message from {address}: message type 8 - request to close connection")
                sender_sock.send("2".encode(FORMAT))
                print(f"Sent message to {address}: message type 2 - acknowledgement")
                print("Connection closed.")
                local_conn_close_event.set()
                break
        except socket.timeout:
            print(f"Timeout reached. Connection closed due to timeout.")
            local_conn_close_event.set()
        time.sleep(5)
    if message_request_event.is_set() or local_switch_event.is_set():
        sender_sock.settimeout(None)


def calculate_crc(data):
    crc_function = crcmod.predefined.Crc('crc-16')
    crc_function.update(data)
    return crc_function.crcValue.to_bytes(2, byteorder='big')


def send_file(sender_sock, path, connection_close_event):
    with open(path, 'rb') as file:
        file_data = file.read()
    min_fragment_size = len(file_data)/32760
    fragment_size = int(input("Enter fragment size, minimum (" + str(math.ceil(min_fragment_size)) + " Bytes): "))
    if len(file_data) < fragment_size:
        total_packets = 1
        fragment_data = file_data
        header = struct.pack('>HHH', len(fragment_data), total_packets, 0)
        crc = calculate_crc(header + fragment_data)
        packet = header + fragment_data + crc
        sender_sock.send(packet)
        acknowledged = False
        while not acknowledged:
            data, address = sender_sock.recvfrom(RECEIVE_SIZE)
            message = data.decode()
            if message[0] == '2':
                print(f"Received message from {address}: message type 2 - acknowledgement")
                acknowledged = True
    else:
        choice = input("Do you want to introduce errors in the message? (y/n): ")
        error = False
        corrupted_packet = -1
        real_packet = None
        if choice == 'y':
            error = True
            corrupted_packet = input("Enter the number of the packet you want to corrupt: ")
        packets = []
        total_packets = (len(file_data) + fragment_size - 1) // fragment_size
        sequence_number = 0
        while sequence_number < total_packets:
            start_idx = sequence_number * fragment_size
            end_idx = (sequence_number + 1) * fragment_size
            fragment_data = file_data[start_idx:end_idx]
            header = struct.pack('>HHH', len(fragment_data), total_packets, sequence_number)
            if error and sequence_number + 1 == int(corrupted_packet):
                crc = "00".encode()
                real_crc = calculate_crc(header + fragment_data)
                real_packet = (header + fragment_data + real_crc)
            else:
                crc = calculate_crc(header + fragment_data)
            packet = (header + fragment_data + crc)
            packets.append(packet)
            sequence_number += 1
        acknowledged = False
        ack_count = 0
        base = 0
        while not acknowledged and not connection_close_event.is_set():
            try:
                sender_sock.send(packets[base])
                print("Sent packet", base + 1, "of", total_packets)
                if error and base == int(corrupted_packet) - 1:
                    packets[base] = real_packet
                    error = False
                try:
                    sender_sock.settimeout(TIMEOUT)
                    while True:
                        data, address = sender_sock.recvfrom(RECEIVE_SIZE)
                        message = data.decode()
                        if message[0] == '2':
                            ack_count += 1
                            print(f"Received message from {address}: message type 2 - acknowledgement")
                            base = ack_count
                            if base == total_packets:
                                acknowledged = True
                                sender_sock.settimeout(TIMEOUT)
                                try:
                                    while True:
                                        data, address = sender_sock.recvfrom(RECEIVE_SIZE)
                                        message = data.decode()
                                        if message[0] == '6':
                                            print(
                                                f"Received message from {address}: message type 6 - data received successfully")
                                            sender_sock.send("2".encode())
                                            print(f"Sent message to {address}: message type 2 - acknowledgement")
                                            sender_sock.settimeout(None)
                                            break
                                except socket.timeout:
                                    sender_sock.settimeout(None)
                                    break
                            break
                        elif message[0] == '3':
                            print(f"Received message from {address}: message type 3 - negative acknowledgement")
                            break
                except socket.timeout:
                    sender_sock.settimeout(None)
                    print("Timeout, retransmitting packet...")
                    continue
            except ConnectionRefusedError:
                print("Connection refused. Press enter to close connection.")
                connection_close_event.set()
                # time.sleep(5)


def send_message(sender_sock, user_message, local_conn_close_event):
    fragment_size = int(input("Enter fragment size: "))
    encoded_message = user_message.encode(FORMAT)
    if len(encoded_message) < fragment_size:
        total_packets = 1
        fragment_data = encoded_message
        header = struct.pack('>HHH', len(fragment_data), total_packets, 0)
        crc = calculate_crc(header + fragment_data)
        packet = header + fragment_data + crc
        sender_sock.send(packet)
        print("Sent packet 1 of 1")
        sender_sock.settimeout(TIMEOUT)
        try:
            while True:
                data, address = sender_sock.recvfrom(RECEIVE_SIZE)
                message = data.decode()
                if message[0] == '6':
                    print(f"Received message from {address}: message type 6 - data received successfully")
                    sender_sock.send("2".encode())
                    print(f"Sent message to {address}: message type 2 - acknowledgement")
                    sender_sock.settimeout(None)
                    break
        except socket.timeout:
            sender_sock.settimeout(None)
            print("Timeout, retransmitting packet...")
            sender_sock.send(packet)
            print("Sent packet 1 of 1")
        except ConnectionRefusedError:
            print("Connection refused. Press enter to close connection.")
            local_conn_close_event.set()
            # time.sleep(5)

    else:
        choice = input("Do you want to introduce errors in the message? (y/n): ")
        error = False
        corrupted_packet = -1
        real_packet = None
        if choice == 'y':
            error = True
            corrupted_packet = input("Enter the number of the packet you want to corrupt: ")
        packets = []
        total_packets = (len(encoded_message) + fragment_size - 1) // fragment_size
        sequence_number = 0
        while sequence_number < total_packets:
            start_idx = sequence_number * fragment_size
            end_idx = (sequence_number + 1) * fragment_size
            fragment_data = encoded_message[start_idx:end_idx]
            header = struct.pack('>HHH', len(fragment_data), total_packets, sequence_number)
            if error and sequence_number + 1 == int(corrupted_packet):
                crc = "00".encode()
                real_crc = calculate_crc(header + fragment_data)
                real_packet = (header + fragment_data + real_crc)
            else:
                crc = calculate_crc(header + fragment_data)
            packet = (header + fragment_data + crc)
            packets.append(packet)
            sequence_number += 1
        acknowledged = False
        ack_count = 0
        base = 0
        while not acknowledged and not local_conn_close_event.is_set():
            try:
                sender_sock.send(packets[base])
                print("Sent packet", base + 1, "of", total_packets)
                if error and base == int(corrupted_packet) - 1:
                    packets[base] = real_packet
                    error = False
                try:
                    sender_sock.settimeout(TIMEOUT)
                    while True:
                        data, address = sender_sock.recvfrom(RECEIVE_SIZE)
                        message = data.decode()
                        if message[0] == '2':
                            ack_count += 1
                            print(f"Received message from {address}: message type 2 - acknowledgement")
                            base = ack_count
                            if base == total_packets:
                                acknowledged = True
                                sender_sock.settimeout(TIMEOUT)
                                try:
                                    while True:
                                        data, address = sender_sock.recvfrom(RECEIVE_SIZE)
                                        message = data.decode()
                                        if message[0] == '6':
                                            print(f"Received message from {address}: message type 6 - data received successfully")
                                            sender_sock.send("2".encode())
                                            print(f"Sent message to {address}: message type 2 - acknowledgement")
                                            sender_sock.settimeout(None)
                                            break
                                except socket.timeout:
                                    sender_sock.settimeout(None)
                                    break
                            break
                        elif message[0] == '3':
                            print(f"Received message from {address}: message type 3 - negative acknowledgement")
                            break
                except socket.timeout:
                    sender_sock.settimeout(None)
                    print("Timeout, retransmitting packet...")
                    continue
            except ConnectionRefusedError:
                print("Connection refused. Press enter to close connection.")
                local_conn_close_event.set()
                # time.sleep(5)

def user_input(sender_sock, DESTINATION, connection_close_event, message_request_event, switch_roles_event):
    local_switch_event = threading.Event()
    local_conn_close_event = threading.Event()
    comm_upkeep_thread = threading.Thread(target=comm_upkeep,
                                          args=(sender_sock, DESTINATION, local_conn_close_event, message_request_event, local_switch_event))
    comm_upkeep_thread.start()
    print("If you want to send a message, type 'message'.")
    print("If you want to send a file, type 'file'.")
    print("If you want to switch roles, type 'switch'.")
    print("If you want to close the connection, type 'close'.")
    choice = input()
    while not switch_roles_event.is_set() and not connection_close_event.is_set():
        if local_switch_event.is_set():
            comm_upkeep_thread.join()
            sender_sock.close()
            switch_roles_event.set()
            break
        if local_conn_close_event.is_set():
            comm_upkeep_thread.join()
            sender_sock.close()
            connection_close_event.set()
            break
        if choice == 'message':
            message_request_event.set()
            comm_upkeep_thread.join()
            sender_sock.send("4".encode(FORMAT))
            print(f"Sent message to {DESTINATION}: message type 4 - message send request")
            sender_sock.settimeout(None)
            acknowledged = False
            while not acknowledged:
                data, address = sender_sock.recvfrom(RECEIVE_SIZE)
                message = data.decode()
                if message[0] == '2':
                    print(f"Received message from {address}: message type 2 - acknowledgement")
                    acknowledged = True
            user_message = input("Enter your message:")
            send_message(sender_sock, user_message, local_conn_close_event)
            message_request_event.clear()
            if not local_conn_close_event.is_set():
                time.sleep(10)
                comm_upkeep_thread = threading.Thread(target=comm_upkeep,
                                                      args=(sender_sock, DESTINATION, local_conn_close_event, message_request_event, local_switch_event))
                comm_upkeep_thread.start()
        elif choice == 'file':
            message_request_event.set()
            comm_upkeep_thread.join()
            sender_sock.send("5".encode(FORMAT))
            print(f"Sent message to {DESTINATION}: message type 5 - file send request")
            acknowledged = False
            while not acknowledged:
                data, address = sender_sock.recvfrom(RECEIVE_SIZE)
                message = data.decode()
                if message[0] == '2':
                    print(f"Received message from {address}: message type 2 - acknowledgement")
                    acknowledged = True
            path = input("Enter the path to the file: ")
            # sender_sock.send(os.path.basename(path).encode(FORMAT))
            print("First need to send file name")
            send_message(sender_sock, os.path.basename(path), local_conn_close_event)
            send_file(sender_sock, path, local_conn_close_event)
            message_request_event.clear()
            if not local_conn_close_event.is_set():
                time.sleep(10)
                comm_upkeep_thread = threading.Thread(target=comm_upkeep,
                                                      args=(sender_sock, DESTINATION, local_conn_close_event, message_request_event, local_switch_event))
                comm_upkeep_thread.start()
        elif choice == 'switch':
            sender_sock.send("7".encode(FORMAT))
            print(f"Sent message to {DESTINATION}: message type 7 - switch roles request")
            acknowledged = False
            while not acknowledged:
                data, address = sender_sock.recvfrom(RECEIVE_SIZE)
                message = data.decode()
                if message[0] == '2':
                    print(f"Received message from {address}: message type 2 - acknowledgement to switch")
                    acknowledged = True
            local_switch_event.set()
            comm_upkeep_thread.join()
            sender_sock.close()
            switch_roles_event.set()
            break
        elif choice == 'close':
            sender_sock.send("8".encode(FORMAT))
            print(f"Sent message to {DESTINATION}: message type 8 - connection close request")
            acknowledged = False
            while not acknowledged:
                data, address = sender_sock.recvfrom(RECEIVE_SIZE)
                message = data.decode()
                if message[0] == '2':
                    print(f"Received message from {address}: message type 2 - acknowledgement")
                    acknowledged = True
            local_conn_close_event.set()
            comm_upkeep_thread.join()
            connection_close_event.set()
            sender_sock.close()
            print("Connection closed.")
            break
        choice = input()


def main(switch_roles_event, connection_close_event, sock, DESTINATION):
    message_request_event = threading.Event()
    sender_sock = sock
    establish_connection(sender_sock, DESTINATION)
    user_input_thread = threading.Thread(target=user_input,
                                         args=(sender_sock, DESTINATION, connection_close_event, message_request_event, switch_roles_event))
    user_input_thread.start()
