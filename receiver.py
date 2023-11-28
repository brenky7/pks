import os
import socket
import struct
import time
import crcmod

RECEIVE_SIZE = 60000
TIMEOUT = 16
FORMAT = 'utf-8'


def establish_connection(receiver_sock):
    established = False
    while not established:
        data, address = receiver_sock.recvfrom(RECEIVE_SIZE)
        message = data.decode()
        if message[0] == '1':
            print(f"Received message from {address}: message type 1 - connect")
            receiver_sock.sendto("2".encode(), address)
            print(f"Sent message to {address}: message type 2 - acknowledgement")
            established = True
        time.sleep(1)


def calculate_crc(data):
    crc_function = crcmod.predefined.Crc('crc-16')
    crc_function.update(data)
    return crc_function.crcValue.to_bytes(2, byteorder='big')


def user_input(receiver_sock, switch_roles_event, connection_closed_event, address):
    print("If you want to switch roles, type 'switch'")
    print("If you want to close the connection, type 'close'")
    print("If you want to continue, type 'continue'")
    choice = input("Choose action: ")
    if choice == "switch":
        receiver_sock.sendto("7".encode(), address)
        print(f"Sent message to {address}: message type 7 - request to switch roles")
        acknowledged = False
        while not acknowledged:
            data, address = receiver_sock.recvfrom(RECEIVE_SIZE)
            message = data.decode()
            if message[0] == '2':
                print(f"Received message from {address}: message type 2 - acknowledgement")
                acknowledged = True
        receiver_sock.close()
        switch_roles_event.set()
    elif choice == "close":
        receiver_sock.sendto("8".encode(), address)
        print(f"Sent message to {address}: message type 8 - request to close connection")
        acknowledged = False
        while not acknowledged:
            data, address = receiver_sock.recvfrom(RECEIVE_SIZE)
            message = data.decode()
            if message[0] == '2':
                print(f"Received message from {address}: message type 2 - acknowledgement")
                acknowledged = True
        connection_closed_event.set()


def receive(receiver_sock, switch_roles_event, connection_closed_event):
    receiver_sock.settimeout(TIMEOUT)
    while not switch_roles_event.is_set() and not connection_closed_event.is_set():
        try:
            data, address = receiver_sock.recvfrom(RECEIVE_SIZE)
            message = data.decode()
            if message[0] == '0':
                receiver_sock.settimeout(TIMEOUT)
                print(f"Received message from {address}: message type 0 - keep alive")
                receiver_sock.sendto("2".encode(), address)
                print(f"Sent message to {address}: message type 2 - acknowledgement")
            elif message[0] == '4':
                receiver_sock.settimeout(None)
                print(f"Received message from {address}: message type 4 - message send request")
                receiver_sock.sendto("2".encode(), address)
                print(f"Sent message to {address}: message type 2 - acknowledgement ")
                receive_message(receiver_sock)
                user_input(receiver_sock, switch_roles_event, connection_closed_event, address)
            elif message[0] == '5':
                receiver_sock.settimeout(None)
                print(f"Received message from {address}: message type 5 - file send request")
                receiver_sock.sendto("2".encode(), address)
                print(f"Sent message to {address}: message type 2 - acknowledgement ")
                receive_file(receiver_sock)
                user_input(receiver_sock, switch_roles_event, connection_closed_event, address)
            elif message[0] == '7':
                receiver_sock.settimeout(None)
                print(f"Received message from {address}: message type 7 - request to switch roles")
                receiver_sock.sendto("2".encode(), address)
                print(f"Sent message to {address}: message type 2 - acknowledgement ")
                receiver_sock.close()
                switch_roles_event.set()
                break
            elif message[0] == '8':
                receiver_sock.settimeout(None)
                print(f"Received message from {address}: message type 8 - connection close request")
                receiver_sock.sendto("2".encode(), address)
                print(f"Sent message to {address}: message type 2 - acknowledgement ")
                receiver_sock.close()
                print("Connection closed.")
                connection_closed_event.set()
                break
        except socket.timeout:
            print("Connection timed out.")
            receiver_sock.close()
            connection_closed_event.set()
            break
    if connection_closed_event.is_set():
        receiver_sock.close()
        print("Connection closed.")


def receive_file(receiver_sock):
    file_name = receive_message(receiver_sock)
    fragments = []
    expected_sequence_number = 0
    while True:
        data, address = receiver_sock.recvfrom(RECEIVE_SIZE)
        header = data[:6]
        fragment_data = data[6:-2]
        received_crc = data[-2:]
        length, total_packets, sequence_number = struct.unpack('>HHH', header)
        calculated_crc = calculate_crc(header + fragment_data)
        if received_crc == calculated_crc and sequence_number == expected_sequence_number:
            fragments.append(fragment_data)
            expected_sequence_number += 1
            print("Received fragment", sequence_number+1, "of", total_packets, ", size: ", length, "Bytes")
            receiver_sock.sendto("2".encode(), address)
            print(f"Sent message to {address}: message type 2 - acknowledgement")
            if expected_sequence_number == total_packets:
                # All fragments received, reconstruct the original message
                reconstructed_message = b''.join(fragments)
                print("Received file:", file_name, ", size: ", len(reconstructed_message), "Bytes")
                receiver_sock.sendto("6".encode(), address)
                print(f"Sent message to {address}: message type 6 - data received successfully")
                acknowledged = False
                while not acknowledged:
                    data, address = receiver_sock.recvfrom(RECEIVE_SIZE)
                    message = data.decode()
                    if message[0] == '2':
                        print(f"Received message from {address}: message type 2 - acknowledgement")
                        acknowledged = True
                break
        elif sequence_number != expected_sequence_number:
            print("Received fragment", sequence_number+1, "of", total_packets, ", size: ", length, "Bytes, unexpected sequence number")
            receiver_sock.sendto("3".encode(), address)
            print(f"Sent message to {address}: message type 3 - negative acknowledgement")
        elif received_crc != calculated_crc:
            print("Received fragment", sequence_number+1, "of", total_packets, ", size: ", length, "Bytes, CRC error")
            receiver_sock.sendto("3".encode(), address)
            print(f"Sent message to {address}: message type 3 - negative acknowledgement")
    choice = input("Where do you want to store the file ? (cwd / absolute path)")
    if choice == "cwd":
        path = os.getcwd()
    else:
        path = choice
    file_path = os.path.join(path, file_name)
    with open(file_path, "wb") as file:
        file.write(reconstructed_message)
    print("File saved at location: ", file_path)


def receive_message(receiver_sock):
    fragments = []
    expected_sequence_number = 0

    while True:
        data, address = receiver_sock.recvfrom(RECEIVE_SIZE)
        header = data[:6]
        fragment_data = data[6:-2]
        received_crc = data[-2:]

        length, total_packets, sequence_number = struct.unpack('>HHH', header)
        calculated_crc = calculate_crc(header + fragment_data)

        if received_crc == calculated_crc and sequence_number == expected_sequence_number:
            fragments.append(fragment_data)
            expected_sequence_number += 1
            print("Received fragment", sequence_number+1, "of", total_packets, ", size: ", length, "Bytes")
            receiver_sock.sendto("2".encode(), address)
            print(f"Sent message to {address}: message type 2 - acknowledgement")

            if expected_sequence_number == total_packets:
                # All fragments received, reconstruct the original message
                reconstructed_message = b''.join(fragments)
                original_message = reconstructed_message.decode(FORMAT)
                print("Received message:", original_message, ", size: ", len(reconstructed_message), "Bytes")
                time.sleep(2)
                receiver_sock.sendto("6".encode(), address)
                print(f"Sent message to {address}: message type 6 - data received successfully")
                acknowledged = False
                while not acknowledged:
                    data, address = receiver_sock.recvfrom(RECEIVE_SIZE)
                    message = data.decode()
                    if message[0] == '2':
                        print(f"Received message from {address}: message type 2 - acknowledgement")
                        acknowledged = True
                break

        elif sequence_number != expected_sequence_number:
            print("Received fragment", sequence_number+1, "of", total_packets, ", size: ", length, "Bytes, unexpected sequence number")
            receiver_sock.sendto("3".encode(), address)
            print(f"Sent message to {address}: message type 3 - negative acknowledgement")
        elif received_crc != calculated_crc:
            print("Received fragment", sequence_number+1, "of", total_packets, ", size: ", length, "Bytes, CRC error")
            receiver_sock.sendto("3".encode(), address)
            print(f"Sent message to {address}: message type 3 - negative acknowledgement")
    return original_message


def main(switch_roles_event, connection_closed_event, sock):
    receiver_sock = sock
    establish_connection(receiver_sock)
    receive(receiver_sock, switch_roles_event, connection_closed_event)




