from collections import defaultdict
from ruamel.yaml.scalarstring import PreservedScalarString
from scapy.all import rdpcap
from scapy.layers.inet import UDP

from MyDictionaries import SAPtypes, ETHERtypes, IPtypes, portsTCP, portsUDP
from MyDictionaries import PIDtypes
import ruamel.yaml

zaznam = "/Users/peterbrenkus/Desktop/skola/sem3/pks/Z1/pcap/trace-15.pcap"
packets = rdpcap(zaznam)
filter = input("Zadajte filter: ")
output = []
counter = 1
if filter == "http":
    print("http")

elif filter == "hhtps":
    print("HTTPS")

elif filter == "telnet":
    print("Telnet")

elif filter == "ssh":
    print("SSH")

elif filter == "ftp-control":
    print("FTP control")

elif filter == "ftp-data":
    print("FTP data")

elif filter == "tftp":
    print("TFTP")

elif filter == "icmp":
    icmp_requests = []
    icmp_responses = []
    icmp_unreachables = []
    complete_comms = []
    incomplete_comms = []
    counter = 1
    for packet in packets:
        hex_data = packet.build().hex()
        EternetType = hex_data[24:28]
        if EternetType == "0800":
            protocolID = hex_data[46:48]
            if protocolID == "01":
                packet_info = {"frame_number": counter}
                manual_len = 0
                for layer in packet:
                    manual_len += len(layer)
                packet_info["len_frame_pcap"] = len(packet)  # zapise dlzku paketu od pcap API
                packet_info["len_frame_medium"] = manual_len + 4
                packet_info["frame_type"] = "Ethernet II"
                DMAC = ""
                for i in range(0, 12, 2):  # zapise Destination MAC
                    DMAC = DMAC + hex_data[i:i + 2] + ":"
                DMAC = DMAC[:-1]
                SMAC = ""
                for i in range(12, 24, 2):  # zapise Source MAC
                    SMAC = SMAC + hex_data[i:i + 2] + ":"
                SMAC = SMAC[:-1]
                packet_info["src_mac"] = SMAC
                packet_info["dst_mac"] = DMAC
                packet_info["ether_type"] = ETHERtypes[EternetType]
                SIP = ""
                for i in range(52, 60, 2):  # zapise Source IP
                    part = f"{int(hex_data[i:i + 2], 16)}"
                    SIP = SIP + part + "."
                SIP = SIP[:-1]
                DIP = ""
                for i in range(60, 68, 2):  # zapise Destination IP
                    part = f"{int(hex_data[i:i + 2], 16)}"
                    DIP = DIP + part + "."
                DIP = DIP[:-1]
                packet_info["src_ip"] = SIP
                packet_info["dst_ip"] = DIP
                packet_info["protocol"] = IPtypes[protocolID]
                icmp_type = hex_data[68:70]
                if icmp_type == "08":
                    packet_info["icmp_type"] = "ECHO REQUEST"
                    packet_info["icmp_id"] = int(hex_data[76:80], 16)
                    packet_info["icmp_seq"] = int(hex_data[80:84], 16)
                    counter2 = 1
                    hexDataFinal = ""
                    for pismeno in hex_data:  # podeli hexa gulas na 2B casti a prida medzery a novy riadok po 16 castiach
                        hexDataFinal += pismeno
                        if counter2 % 2 == 0 and counter2 % 32 != 0:
                            hexDataFinal += ' '
                        elif counter2 % 32 == 0:
                            hexDataFinal += '\n'
                        counter2 += 1
                    packet_info["hexa_frame"] = PreservedScalarString(hexDataFinal)
                    icmp_requests.append(packet_info)
                elif icmp_type == "00":
                    packet_info["icmp_type"] = "ECHO REPLY"
                    packet_info["icmp_id"] = int(hex_data[76:80], 16)
                    packet_info["icmp_seq"] = int(hex_data[80:84], 16)
                    counter2 = 1
                    hexDataFinal = ""
                    for pismeno in hex_data:  # podeli hexa gulas na 2B casti a prida medzery a novy riadok po 16 castiach
                        hexDataFinal += pismeno
                        if counter2 % 2 == 0 and counter2 % 32 != 0:
                            hexDataFinal += ' '
                        elif counter2 % 32 == 0:
                            hexDataFinal += '\n'
                        counter2 += 1
                    packet_info["hexa_frame"] = PreservedScalarString(hexDataFinal)
                    icmp_responses.append(packet_info)
                elif icmp_type == "03":
                    packet_info["icmp_type"] = "Destination unreachable"
                    counter2 = 1
                    hexDataFinal = ""
                    for pismeno in hex_data:  # podeli hexa gulas na 2B casti a prida medzery a novy riadok po 16 castiach
                        hexDataFinal += pismeno
                        if counter2 % 2 == 0 and counter2 % 32 != 0:
                            hexDataFinal += ' '
                        elif counter2 % 32 == 0:
                            hexDataFinal += '\n'
                        counter2 += 1
                    packet_info["hexa_frame"] = PreservedScalarString(hexDataFinal)
                    icmp_unreachables.append(packet_info)
        counter += 1
    communication = {}
    pakety = []
    counter3 = 1
    ids = []
    for request in icmp_requests:
        icmp_id = request["icmp_id"]
        if ids.__contains__(icmp_id):
            continue
        else:
            ids.append(icmp_id)
    for id in ids:
        for request in icmp_requests:
            if request["icmp_id"] == id:
                pakety.append(request)
                for reply in icmp_responses:
                    if reply["icmp_id"] == id and reply["icmp_seq"] == request["icmp_seq"]:
                        pakety.append(reply)
                        break
        communication["number_comm"] = counter3
        communication["src_ip"] = pakety[0]["src_ip"]
        communication["dst_ip"] = pakety[0]["dst_ip"]
        communication["packets"] = pakety
        complete_comms.append(communication)
        pakety = []
        communication = {}
        counter3 += 1
    complete_comms_clean = []
    incomplete_comms_clean = []
    for comm in complete_comms:
       for packet in comm["packets"]:
            if packet in icmp_requests:
                icmp_requests.remove(packet)
            elif packet in icmp_responses:
                icmp_responses.remove(packet)
    for request in icmp_requests:
        incomplete_comms.append(request)
    for reply in icmp_responses:
        incomplete_comms.append(reply)
    for unreachable in icmp_unreachables:
        incomplete_comms.append(unreachable)
    for comm in complete_comms:
        cleaned_comm = comm.copy()
        cleaned_comm["packets"] = [packet.copy() for packet in comm['packets']]
        complete_comms_clean.append(cleaned_comm)
    for comm in incomplete_comms:
        cleaned_comm = comm.copy()
        incomplete_comms_clean.append(cleaned_comm)
    file_output = {"name": "PKS2023/24", "pcap_name": "icmp.pcap", "filter_name": "ICMP", "complete_comms": complete_comms_clean, "incomplete_comms": incomplete_comms_clean}
    with open("output.yaml", "w") as file:
        ruamel.yaml.dump(file_output, file, default_style='', default_flow_style=False, Dumper=ruamel.yaml.RoundTripDumper)

elif filter == "arp":
    arp_requests = []
    arp_replies = []
    complete_comms = []
    incomplete_comms = []
    counter = 1
    for packet in packets:
        hex_data = packet.build().hex()
        EternetType = hex_data[24:28]
        if int(EternetType, 16) > 1500:
            if ETHERtypes[EternetType] == "ARP":
                packet_info = {"frame_number": counter}  # vytvori slovnik s informaciami o pakete
                DMAC = ""
                for i in range(0, 12, 2):  # zapise Destination MAC
                    DMAC = DMAC + hex_data[i:i + 2] + ":"
                DMAC = DMAC[:-1]
                SMAC = ""
                for i in range(12, 24, 2):  # zapise Source MAC
                    SMAC = SMAC + hex_data[i:i + 2] + ":"
                SMAC = SMAC[:-1]
                packet_info["src_mac"] = SMAC
                packet_info["dst_mac"] = DMAC
                manual_len = 0
                for layer in packet:
                    manual_len += len(layer)
                packet_info["len_frame_pcap"] = len(packet)  # zapise dlzku paketu od pcap API
                packet_info["len_frame_medium"] = manual_len + 4
                packet_info["frame_type"] = "Ethernet II"
                packet_info["ether_type"] = ETHERtypes[EternetType]
                type = hex_data[40:44]
                if type == "0001":
                    packet_info["operation"] = "request"
                    target_ip = ""
                    for i in range(56, 64, 2):  # zapise Destination IP
                        part = f"{int(hex_data[i:i + 2], 16)}"
                        target_ip = target_ip + part + "."
                    target_ip = target_ip[:-1]
                    packet_info["target_ip"] = target_ip
                    arp_requests.append(packet_info)
                elif type == "0002":
                    packet_info["operation"] = "reply"
                    target_ip = ""
                    for i in range(56, 64, 2):  # zapise Destination IP
                        part = f"{int(hex_data[i:i + 2], 16)}"
                        target_ip = target_ip + part + "."
                    target_ip = target_ip[:-1]
                    packet_info["target_ip"] = target_ip
                    target_mac = ""
                    for i in range(44, 56, 2):
                        part = f"{hex_data[i:i + 2]}"
                        target_mac = target_mac + part + ":"
                    target_mac = target_mac[:-1]
                    packet_info["target_mac"] = target_mac
                    arp_replies.append(packet_info)
                counter2 = 1
                hexDataFinal = ""
                for pismeno in hex_data:  # podeli hexa gulas na 2B casti a prida medzery a novy riadok po 16 castiach
                    hexDataFinal += pismeno
                    if counter2 % 2 == 0 and counter2 % 32 != 0:
                        hexDataFinal += ' '
                    elif counter2 % 32 == 0:
                        hexDataFinal += '\n'
                    counter2 += 1
                packet_info["hexa_frame"] = PreservedScalarString(hexDataFinal)
        counter += 1
    for request in arp_requests:
        for reply in arp_replies:
            if request["dst_mac"] == reply["src_mac"]:
                complete_comms.append(request)
                complete_comms.append(reply)
                arp_replies.remove(reply)
                arp_requests.remove(request)
                break
    for request in arp_requests:
        incomplete_comms.append(request)
    for reply in arp_replies:
        incomplete_comms.append(reply)
    output.append({"name": "PKS2023/24"})
    output.append({"pcap_name": "arp.pcap"})
    output.append({"filter_name": "ARP"})
    output.append({"complete_comms": complete_comms})
    output.append({"incomplete_comms": incomplete_comms})
    with open("output.yaml", "w") as file:
        ruamel.yaml.dump(output, file, Dumper=ruamel.yaml.RoundTripDumper)

print(output)
