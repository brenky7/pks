from collections import defaultdict
from ruamel.yaml.scalarstring import PreservedScalarString
from scapy.all import rdpcap
from MyDictionaries import SAPtypes, ETHERtypes, IPtypes, portsTCP, portsUDP, PIDtypes
import ruamel.yaml

zaznam = "/Users/peterbrenkus/Desktop/skola/sem3/pks/Z1/pcap/trace-15.pcap"
packets = rdpcap(zaznam)
filter = input("Zadajte filter: ")
output = []
counter = 1
ipstat = []
ipwin = []
IpStatistics = defaultdict(int)
for packet in packets:
    hex_data = packet.build().hex()
    EternetType = hex_data[24:28]
    TypLLC = f"{hex_data[28:30]}"
    DMAC = ""
    for i in range(0, 12, 2):       #zapise Destination MAC
        DMAC = DMAC + hex_data[i:i+2] + ":"
    DMAC = DMAC[:-1]
    SMAC = ""
    for i in range(12, 24, 2):      #zapise Source MAC
        SMAC = SMAC + hex_data[i:i+2] + ":"
    SMAC = SMAC[:-1]
    packet_info = {"frame_number": counter}     #vytvori slovnik s informaciami o pakete
    packet_info["len_frame_pcap"] = len(packet.payload)
    manual_len = 0
    for layer in packet:
        manual_len += len(layer)
    if manual_len < 64:
        packet_info["len_frame_medium"] = 64
    else:
        packet_info["len_frame_medium"] = manual_len + 4
        #zapise dlzku paketu od pcap API
       #zapise dlzku paketu manualne vypocitanu + 4B pre FCS
    if int(EternetType, 16) > 1500:                 #ak je EthernetType vacsi ako 1500, tak je to Ethernet II
        packet_info["frame_type"] = "Ethernet II"
        if EternetType in ETHERtypes:
            packet_info["ether_type"] = ETHERtypes[EternetType]  #zisti ether_type a zapise ho do slovnika
        else :
            packet_info["ether_type"] = "unknown"
        if packet_info["ether_type"] == "IPv4":
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
            IpStatistics[SIP] += 1
            packet_info["dst_ip"] = DIP
            if IPtypes[hex_data[46:48]] == "TCP":
                packet_info["protocol"] = IPtypes[hex_data[46:48]]
                if f"{int(hex_data[68:72], 16)}" in portsTCP:
                    packet_info["src_port"] = portsTCP[f"{int(hex_data[68:72], 16)}"]
                else:
                    packet_info["src_port"] = int(hex_data[68:72], 16)
                if f"{int(hex_data[72:76], 16)}" in portsTCP:
                    packet_info["dst_port"] = portsTCP[f"{int(hex_data[72:76], 16)}"]
                else:
                    packet_info["dst_port"] = int(hex_data[72:76], 16)
            elif IPtypes[hex_data[46:48]] == "UDP":
                packet_info["protocol"] = IPtypes[hex_data[46:48]]
                if f"{int(hex_data[68:72], 16)}" in portsUDP:
                    packet_info["src_port"] = portsUDP[f"{int(hex_data[68:72], 16)}"]
                else:
                    packet_info["src_port"] = int(hex_data[68:72], 16)
                if f"{int(hex_data[72:76], 16)}" in portsUDP:
                    packet_info["dst_port"] = portsUDP[f"{int(hex_data[72:76], 16)}"]
                else:
                    packet_info["dst_port"] = int(hex_data[72:76], 16)
            else:
                packet_info["protocol"] = IPtypes[hex_data[46:48]]
        elif packet_info["ether_type"] == "IPv6":
            SIP = ""
            for i in range(44, 76, 4):
                part = f"{hex_data[i:i + 4]}"
                if part[0] == "0":
                    part = part[1:]
                SIP = SIP + part + ":"
            SIP = SIP[:-1]
            SIP = SIP.replace("000:", "")
            SIP = SIP[0:4] + ":" + SIP[4:]
            DIP = ""
            for i in range(76, 108, 4):
                part = f"{hex_data[i:i + 4]}"
                if part[0] == "0":
                    part = part[1:]
                DIP = DIP + part + ":"
            DIP = DIP[:-1]
            DIP = DIP.replace("000:", "")
            DIP = DIP[0:4] + ":" + DIP[4:]
            packet_info["src_ip"] = SIP
            packet_info["dst_ip"] = DIP
        packet_info["src_mac"] = SMAC
        packet_info["dst_mac"] = DMAC
    elif TypLLC == "aa":
        packet_info["frame_type"] = "IEEE 802.3 LLC & SNAP"     #ak je TypLLC aa, tak je to LLC & SNAP
        if f"{hex_data[40:44]}" in PIDtypes:
            packet_info["src_mac"] = SMAC
            packet_info["dst_mac"] = DMAC
            packet_info["pid"] = PIDtypes[hex_data[40:44]]      #zisti pid a zapise ho do slovnika
        else:
            packet_info["src_mac"] = SMAC
            packet_info["dst_mac"] = DMAC
            packet_info["pid"] = PIDtypes[hex_data[92:96]]      #toto riesi 18. frame z trace-26.pcap
    elif TypLLC == "ff":                                        #ak je TypLLC ff, tak je to IEEE 802.3 RAW
        packet_info["frame_type"] = "IEEE 802.3 RAW"
        packet_info["src_mac"] = SMAC
        packet_info["dst_mac"] = DMAC
    else:
        packet_info["frame_type"] = "IEEE 802.3 LLC"            #ak je TypLLC nieco ine, tak je to IEEE 802.3 LLC
        packet_info["src_mac"] = SMAC
        packet_info["dst_mac"] = DMAC
        packet_info["sap"] = SAPtypes[hex_data[30:32]]          #zisti sap a zapise ho do slovnika
    counter2 = 1
    hexDataFinal = ""
    for pismeno in hex_data:     #podeli hexa gulas na 2B casti a prida medzery a novy riadok po 16 castiach
        hexDataFinal += pismeno
        if counter2 % 2 == 0 and counter2 % 32 != 0:
            hexDataFinal += ' '
        elif counter2 % 32 == 0:
            hexDataFinal += '\n'
        counter2 += 1
    packet_info["hexa_frame"] = PreservedScalarString(hexDataFinal)
    output.append(packet_info)
    counter += 1
maximum = 0
for i in IpStatistics:
    if IpStatistics[i] > maximum:
        maximum = IpStatistics[i]
    ipstat.append({"node": i, "number_of_sent_packets": IpStatistics[i]})   #vytvori slovnik s ip adresami a ich poctom vyskytov
for i in IpStatistics:
    if IpStatistics[i] == maximum:
        ipwin.append(i)
fileOutput = {"name": "PKS2023/24", "pcap_name": "trace-26.pcap", "packets": output, "ipv4 senders": ipstat, "max_send_packets_by": ipwin}    #vytvori finalny slovnik ktory sa da do yaml
with open("paketyAll.yaml", "w") as yaml_file:

    ruamel.yaml.dump(fileOutput, yaml_file, Dumper=ruamel.yaml.RoundTripDumper)
packets = rdpcap(zaznam)
counter = 1
output = {}
if filter == "HTTP" or filter == "HTTPS" or filter == "Telnet" or filter == "SSH" or filter == "FTP-control" or filter == "FTP-data":
    tcp_pakety = []
    for packet in packets:
        hex_data = packet.build().hex()
        EternetType = hex_data[24:28]
        if int(EternetType,16) > 600:
            ip_type = hex_data[46:48]
            if ip_type in IPtypes and IPtypes[ip_type] == "TCP":
                packet_info = {"frame_number": counter}
                manual_len = 0
                for layer in packet:
                    manual_len += len(layer)
                packet_info["len_frame_pcap"] = len(packet)  # zapise dlzku paketu od pcap API
                if manual_len < 64:
                    packet_info["len_frame_medium"] = 64
                else:
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
                packet_info["protocol"] = IPtypes[ip_type]
                packet_info["src_port"] = int(hex_data[68:72], 16)
                packet_info["dst_port"] = int(hex_data[72:76], 16)
                if f"{int(hex_data[68:72], 16)}" in portsTCP:
                    packet_info["app_protocol"] = portsTCP[f"{int(hex_data[68:72], 16)}"]
                if f"{int(hex_data[72:76], 16)}" in portsTCP:
                    packet_info["app_protocol"] = portsTCP[f"{int(hex_data[72:76], 16)}"]
                flag_decimal = int(hex_data[92:96], 16)
                flags_binary = bin(flag_decimal)[2:].zfill(16)
                flags = []
                if flags_binary[11] == "1":
                    flags.append("ACK")
                if flags_binary[12] == "1":
                    flags.append("PSH")
                if flags_binary[13] == "1":
                    flags.append("RST")
                if flags_binary[14] == "1":
                    flags.append("SYN")
                if flags_binary[15] == "1":
                    flags.append("FIN")
                packet_info["tcp_flags"] = flags
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
                if packet_info["protocol"] == "TCP" and packet_info["ether_type"] == "IPv4":
                    tcp_pakety.append(packet_info)
        counter += 1
    comm_number = 1
    communication = {}
    zaciatky = []
    for index in range(len(tcp_pakety)):
        if "SYN" in tcp_pakety[index]["tcp_flags"] and "ACK" not in tcp_pakety[index]["tcp_flags"]:
            communication["number_comm"] = comm_number
            communication["src_comm"] = tcp_pakety[index]["src_ip"]
            communication["dst_comm"] = tcp_pakety[index]["dst_ip"]
            communication["packets"] = []
            communication["packets"].append(tcp_pakety[index])
            comm_number += 1
            zaciatky.append(communication)
            communication = {}
            communication["packets"] = []
    comms = []
    for zaciatok in zaciatky:
        for packet in tcp_pakety:
            if packet["src_ip"] == zaciatok["packets"][0]["src_ip"] and packet["dst_ip"] == zaciatok["packets"][0]["dst_ip"] and packet["src_port"] == zaciatok["packets"][0]["src_port"] and packet["dst_port"] == zaciatok["packets"][0]["dst_port"]:
                zaciatok["packets"].append(packet)
            if packet["src_ip"] == zaciatok["packets"][0]["dst_ip"] and packet["dst_ip"] == zaciatok["packets"][0]["src_ip"] and packet["src_port"] == zaciatok["packets"][0]["dst_port"] and packet["dst_port"] == zaciatok["packets"][0]["src_port"]:
                zaciatok["packets"].append(packet)
    complete_comms = []
    incomplete_comms = []
    for comm in zaciatky:
        zaciatok = False
        koniec = False
        del comm["packets"][0]
        if len(comm["packets"]) > 4:
            if "SYN" in comm["packets"][0]["tcp_flags"] and "ACK" in comm["packets"][1]["tcp_flags"] and "SYN" in comm["packets"][1]["tcp_flags"]and "ACK" in comm["packets"][2]["tcp_flags"]:
               zaciatok = True
            if "SYN" in comm["packets"][0]["tcp_flags"] and "SYN" in comm["packets"][1]["tcp_flags"] and "ACK" in comm["packets"][0]["tcp_flags"]and "ACK" in comm["packets"][1]["tcp_flags"]:
               zaciatok = True
            if "FIN" in comm["packets"][-4]["tcp_flags"] and "ACK" in comm["packets"][-3]["tcp_flags"] and "FIN" in comm["packets"][-2]["tcp_flags"] and "ACK" in comm["packets"][-1]["tcp_flags"]:
                koniec = True
            if "FIN" in comm["packets"][-4]["tcp_flags"] and "FIN" in comm["packets"][-3]["tcp_flags"] and "ACK" in comm["packets"][-2]["tcp_flags"] and "ACK" in comm["packets"][-1]["tcp_flags"]:
                koniec = True
            if "FIN" in comm["packets"][-3]["tcp_flags"] and "ACK" in comm["packets"][-3]["tcp_flags"] and "FIN" in comm["packets"][-2]["tcp_flags"] and "ACK" in comm["packets"][-2]["tcp_flags"] and "ACK" in comm["packets"][-1]["tcp_flags"]:
                koniec = True
            if "RST" in comm["packets"][-1]["tcp_flags"]:
                koniec = True
        if zaciatok == True and koniec == True:
            complete_comms.append(comm)
    complete_comms_sorted = []
    for comm in complete_comms:
        komunikacia = {}
        komunikacia["number_comm"] = comm["number_comm"]
        komunikacia["src_comm"] = comm["src_comm"]
        komunikacia["dst_comm"] = comm["dst_comm"]
        komunikacia["packets"] = comm["packets"]
        complete_comms_sorted.append(komunikacia)
        for packet in comm["packets"]:
            if packet in tcp_pakety:
                tcp_pakety.remove(packet)
    for packet in tcp_pakety:
        if packet["protocol"]  != "TCP":
            tcp_pakety.remove(packet)
    comm_number = 1
    incomplete_comms_clean = []
    tcp_pakety_2 = []
    for packet in tcp_pakety:
        if packet["app_protocol"] == filter:
            tcp_pakety_2.append(packet)
    if len(tcp_pakety_2) > 0:
        src_port = tcp_pakety_2[0]["src_port"]
        dst_port = tcp_pakety_2[0]["dst_port"]
        communication = {}
        communication["number_comm"] = comm_number
        communication["packets"] = []
        communication["packets"].append(tcp_pakety_2[0])
        tcp_pakety_2.remove(tcp_pakety_2[0])
        for packet in tcp_pakety_2:
            if packet["src_port"] == src_port and packet["dst_port"] == dst_port:
                communication["packets"].append(packet)
            elif packet["src_port"] == dst_port and packet["dst_port"] == src_port:
                communication["packets"].append(packet)
        incomplete_comms.append(communication)
        index = 0
        for comm in incomplete_comms:
            for paket in comm["packets"]:
                if paket["src_port"] == filter or paket["dst_port"] == filter:
                    index = incomplete_comms.index(comm)
                    break
        cleaned_comm = incomplete_comms[index].copy()
        cleaned_comm["packets"] = []
        for packet in incomplete_comms[index]['packets']:
            cleaned_packet = packet.copy()
            del cleaned_packet["tcp_flags"]
            # if isinstance(cleaned_packet.get("tcp_flags"), list):
            #     cleaned_packet["tcp_flags"] = cleaned_packet["tcp_flags"][:]
            cleaned_comm["packets"].append(cleaned_packet)
        incomplete_comms_clean.append(cleaned_comm)
    complete_comms_clean = []
    for comm in complete_comms_sorted:
        cleaned_comm = comm.copy()
        cleaned_comm["packets"] = []
        for packet in comm['packets']:
            cleaned_packet = packet.copy()
            # if isinstance(cleaned_packet.get("tcp_flags"), list):
            #     cleaned_packet["tcp_flags"] = cleaned_packet["tcp_flags"][:]
            del cleaned_packet["tcp_flags"]
            cleaned_comm["packets"].append(cleaned_packet)
        complete_comms_clean.append(cleaned_comm)
    complete_final = []
    incomplete_final = []
    if filter == "HTTP":
        for comm in complete_comms_clean:
            for packet in comm["packets"]:
                if packet["app_protocol"] == "HTTP":
                    complete_final.append(comm)
                    break
        for comm in incomplete_comms_clean:
            for packet in comm["packets"]:
                if packet["app_protocol"] == "HTTP":
                    incomplete_final.append(comm)
                    break
    elif filter == "HTTPS":
        for comm in complete_comms_clean:
            for packet in comm["packets"]:
                if packet["app_protocol"] == "HTTPS":
                    complete_final.append(comm)
                    break
        for comm in incomplete_comms_clean:
            for packet in comm["packets"]:
                if packet["app_protocol"] == "HTTPS":
                    incomplete_final.append(comm)
                    break
    elif filter == "Telnet":
        for comm in complete_comms_clean:
            for packet in comm["packets"]:
                if packet["app_protocol"] == "Telnet":
                    complete_final.append(comm)
                    break
        for comm in incomplete_comms_clean:
            for packet in comm["packets"]:
                if packet["app_protocol"] == "Telnet":
                    incomplete_final.append(comm)
                    break
    elif filter == "SSH":
        for comm in complete_comms_clean:
            for packet in comm["packets"]:
                if packet["app_protocol"] == "SSH":
                    complete_final.append(comm)
                    break
        for comm in incomplete_comms_clean:
            for packet in comm["packets"]:
                if packet["app_protocol"] == "SSH":
                    incomplete_final.append(comm)
                    break
    elif filter == "FTP-control":
        for comm in complete_comms_clean:
            for packet in comm["packets"]:
                if packet["app_protocol"] == "FTP-control":
                    complete_final.append(comm)
                    break
        for comm in incomplete_comms_clean:
            for packet in comm["packets"]:
                if packet["app_protocol"] == "FTP-control":
                    incomplete_final.append(comm)
                    break
    elif filter == "FTP-data":
        for comm in complete_comms_clean:
            for packet in comm["packets"]:
                if packet["app_protocol"] == "FTP-data":
                  complete_final.append(comm)
                  break
        for comm in incomplete_comms_clean:
            for packet in comm["packets"]:
                if packet["app_protocol"] == "FTP-data":
                    incomplete_final.append(comm)
                    break
    output["name"] = "PKS2023/24"
    output["pcap_name"] = "http.pcap"
    output["filter_name"] = "HTTP"
    output["complete_comms"] = complete_final
    output["partial_comms"] = incomplete_final
    with open("output.yaml", "w") as file:
        ruamel.yaml.dump(output, file, Dumper=ruamel.yaml.RoundTripDumper)

elif filter == "tftp":
    udp_pakety = []
    counter = 1
    for packet in packets:
        hex_data = packet.build().hex()
        EternetType = hex_data[24:28]
        if EternetType == "0800":
            ip_type = hex_data[46:48]
            if ip_type == "11":
                paket_info = {"frame_number": counter}
                manual_len = 0
                for layer in packet:
                    manual_len += len(layer)
                paket_info["len_frame_pcap"] = len(packet)  # zapise dlzku paketu od pcap API
                if manual_len < 64:
                    paket_info["len_frame_medium"] = 64
                else:
                    paket_info["len_frame_medium"] = manual_len + 4
                paket_info["frame_type"] = "Ethernet II"
                DMAC = ""
                for i in range(0, 12, 2):  # zapise Destination MAC
                    DMAC = DMAC + hex_data[i:i + 2] + ":"
                DMAC = DMAC[:-1]
                SMAC = ""
                for i in range(12, 24, 2):  # zapise Source MAC
                    SMAC = SMAC + hex_data[i:i + 2] + ":"
                SMAC = SMAC[:-1]
                paket_info["src_mac"] = SMAC
                paket_info["dst_mac"] = DMAC
                paket_info["ether_type"] = ETHERtypes[EternetType]
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
                paket_info["src_ip"] = SIP
                paket_info["dst_ip"] = DIP
                paket_info["protocol"] = IPtypes[ip_type]
                if f"{int(hex_data[68:72], 16)}" in portsUDP:
                    paket_info["src_port"] = portsUDP[f"{int(hex_data[68:72], 16)}"]
                    paket_info["app_protocol"] = paket_info["src_port"]
                else:
                    paket_info["src_port"] = int(hex_data[68:72], 16)
                if f"{int(hex_data[72:76], 16)}" in portsUDP:
                    paket_info["dst_port"] = portsUDP[f"{int(hex_data[72:76], 16)}"]
                    paket_info["app_protocol"] = paket_info["dst_port"]
                else:
                    paket_info["dst_port"] = int(hex_data[72:76], 16)
                paket_info["hexa_frame"] = PreservedScalarString(hex_data)
                udp_pakety.append(paket_info)
        counter += 1
    tftp_pakety = []
    for paket in udp_pakety:
        src_port = paket["hexa_frame"][68:72]
        dst_port = paket["hexa_frame"][72:76]
        if dst_port == "0045":
            paket["protocol"] = "TFTP"
            tftp_pakety.append(paket)
    for paket in udp_pakety:
        if paket in tftp_pakety:
            udp_pakety.remove(paket)
    comms = []
    communication = {}
    pakety = []
    counter2 = 1
    server_port = ""
    client_port = ""
    for zaciatok in tftp_pakety:
        client_port = zaciatok["src_port"]
        done = False
        for paket in udp_pakety:
            if paket["dst_port"] == client_port and done == False:
                server_port = paket["src_port"]
                pakety.append(zaciatok)
                pakety.append(paket)
                communication["number_comm"] = counter2
                done = True
            elif paket["src_port"] == server_port and paket["dst_port"] == client_port:
                pakety.append(paket)
            elif paket["src_port"] == client_port and paket["dst_port"] == server_port:
                pakety.append(paket)
        server_port = ""
        client_port = ""
        for paket in pakety:
            paket["tftp_opcode"] = int(paket["hexa_frame"][84:88], 16)
            counter3 = 1
            hex_data_final = ""
            for pismeno in paket["hexa_frame"]:  # podeli hexa gulas na 2B casti a prida medzery a novy riadok po 16 castiach
                hex_data_final += pismeno
                if counter3 % 2 == 0 and counter3 % 32 != 0:
                    hex_data_final += ' '
                elif counter3 % 32 == 0:
                    hex_data_final += '\n'
                counter3 += 1
            paket["hexa_frame"] = PreservedScalarString(hex_data_final)
        communication["packets"] = pakety
        counter2 += 1
        pakety = []
        comms.append(communication)
        communication = {}
    complete_comms = []
    incomplete_comms = []
    for comm in comms:
        if comm["packets"][-2]["tftp_opcode"] == 3 and comm["packets"][-1]["tftp_opcode"] == 4:
            complete_comms.append(comm)
        else:
            incomplete_comms.append(comm)
    complete_comms_clean = []
    for comm in complete_comms:
        cleaned_comm = comm.copy()
        cleaned_comm["packets"] = [packet.copy() for packet in comm['packets']]
        complete_comms_clean.append(cleaned_comm)
    for comm in complete_comms_clean:
        for packet in comm["packets"]:
            if "tftp_opcode" in packet:
                del packet["tftp_opcode"]
            if packet["protocol"] == "TFTP":
                packet["protocol"] = "UDP"
            if packet["src_port"] == "TFTP":
                packet["src_port"] = 69
            if packet["dst_port"] == "TFTP":
                packet["dst_port"] = 69

    incomplete_comms_clean = []
    for comm in incomplete_comms:
        cleaned_comm = comm.copy()
        cleaned_comm["packets"] = [packet.copy() for packet in comm['packets']]
        incomplete_comms_clean.append(cleaned_comm)
    for comm in incomplete_comms_clean:
        for packet in comm["packets"]:
            if "tftp_opcode" in packet:
                del packet["tftp_opcode"]
            if packet["protocol"] == "TFTP":
                packet["protocol"] = "UDP"
            if packet["src_port"] == "TFTP":
                packet["src_port"] = 69
            if packet["dst_port"] == "TFTP":
                packet["dst_port"] = 69
    output["name"] = "PKS2023/24"
    output["pcap_name"] = "tftp.pcap"
    output["filter_name"] = "TFTP"
    output["complete_comms"] = complete_comms_clean
    output["partial_comms"] = incomplete_comms_clean
    with open("output.yaml", "w") as file:
        ruamel.yaml.dump(output, file, Dumper=ruamel.yaml.RoundTripDumper)

elif filter == "icmp":
    icmp_requests = []
    icmp_responses = []
    icmp_unreachables = []
    complete_comms = []
    incomplete_comms = []
    ip_pakety = []
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
                if manual_len < 64:
                    packet_info["len_frame_medium"] = 64
                else:
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
                elif icmp_type == "11":
                    packet_info["icmp_type"] = "Time exceeded"
                    counter2 = 1
                    hexDataFinal = ""
                    for pismeno in hex_data:
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
    packets = rdpcap(zaznam)
    counter = 1
    zaciatky = []
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
                packet_info["len_frame_pcap"] = len(packet)
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
                flag = hex_data[40:42]
                decimal = int(flag, 16)
                binary_flag = bin(decimal)[2:].zfill(8)
                if binary_flag[2] == "1":
                    packet_info["flag"] = "more fragments"
                    packet_info["hexa_frame"] = hex_data
                    zaciatky.append(packet_info)
                else:
                    packet_info["hexa_frame"] = hex_data
                    ip_pakety.append(packet_info)
        counter += 1
    fragmented_comms = []
    communication = {}
    counter4 = 1
    paketyComm = []
    for zaciatok in zaciatky:
        zaciatok_id = zaciatok["hexa_frame"][36:40]
        zaciatok["id_fragment"] = zaciatok_id
        fragment_offset = zaciatok["hexa_frame"][42:44]
        if fragment_offset == "00":
            zaciatok["fragment_offset"] = 0
        counter5= 1
        hexDataFinal = ""
        for pismeno in zaciatok["hexa_frame"]:  # podeli hexa gulas na 2B casti a prida medzery a novy riadok po 16 castiach
            hexDataFinal += pismeno
            if counter5 % 2 == 0 and counter5 % 32 != 0:
                hexDataFinal += ' '
            elif counter5 % 32 == 0:
                hexDataFinal += '\n'
            counter5 += 1
        zaciatok["hexa_frame"] = PreservedScalarString(hexDataFinal)
        done = False
        for paket in ip_pakety:
            paket_id = paket["hexa_frame"][36:40]
            if zaciatok["src_ip"] == paket["src_ip"] and zaciatok["dst_ip"] == paket["dst_ip"] and zaciatok_id == paket_id and done == False:
                paket["id_fragment"] = paket_id
                fragment_offset = paket["hexa_frame"][42:44]
                if fragment_offset == "b9":
                    paket["fragment_offset"] = 1480
                paketyComm.append(zaciatok)
                counter5 = 1
                hexDataFinal = ""
                for pismeno in paket["hexa_frame"]:  # podeli hexa gulas na 2B casti a prida medzery a novy riadok po 16 castiach
                    hexDataFinal += pismeno
                    if counter5 % 2 == 0 and counter5 % 32 != 0:
                        hexDataFinal += ' '
                    elif counter5 % 32 == 0:
                        hexDataFinal += '\n'
                    counter5 += 1
                paket["hexa_frame"] = PreservedScalarString(hexDataFinal)
                paketyComm.append(paket)
                done = True
                communication["number_fragment"] = counter4
                communication["src_ip"] = paket["src_ip"]
                communication["dst_ip"] = paket["dst_ip"]
            elif zaciatok["src_ip"] == paket["src_ip"] and zaciatok["dst_ip"] == paket["dst_ip"] and zaciatok_id == paket_id:
                paket["id_fragment"] = paket_id
                fragment_offset = paket["hexa_frame"][42:44]
                if fragment_offset == "b9":
                    paket["fragment_offset"] = 1480
                counter5 = 1
                hexDataFinal = ""
                for pismeno in zaciatok[
                    "hexa_frame"]:  # podeli hexa gulas na 2B casti a prida medzery a novy riadok po 16 castiach
                    hexDataFinal += pismeno
                    if counter5 % 2 == 0 and counter5 % 32 != 0:
                        hexDataFinal += ' '
                    elif counter5 % 32 == 0:
                        hexDataFinal += '\n'
                    counter5 += 1
                paket["hexa_frame"] = PreservedScalarString(hexDataFinal)
                paketyComm.append(paket)
        communication["packets"] = paketyComm
        fragmented_comms.append(communication)
        paketyComm = []
        communication = {}
        counter4 += 1

    file_output = {"name": "PKS2023/24", "pcap_name": "icmp.pcap", "filter_name": "ICMP","complete_comms": complete_comms_clean, "partial_comms": incomplete_comms_clean, "fragmented_packets": fragmented_comms}
    with open("output.yaml", "w") as file:
        ruamel.yaml.dump(file_output, file, default_style='', default_flow_style=False, Dumper=ruamel.yaml.RoundTripDumper)
    # file_output = {"name": "PKS2023/24", "pcap_name": "icmp.pcap", "filter_name": "ICMP", "complete_comms": complete_comms_clean, "incomplete_comms": incomplete_comms_clean}
    # with open("output.yaml", "w") as file:
    #     ruamel.yaml.dump(file_output, file, default_style='', default_flow_style=False, Dumper=ruamel.yaml.RoundTripDumper)

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
                manual_len = 0
                for layer in packet:
                    manual_len += len(layer)
                packet_info["len_frame_pcap"] = len(packet)  # zapise dlzku paketu od pcap API
                if manual_len < 64:
                    packet_info["len_frame_medium"] = 64
                else:
                    packet_info["len_frame_medium"] = manual_len + 4
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
                    packet_info["flag"] = "unused"
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
    pakety = []
    communication = {}
    counter3 = 1
    for request in arp_requests:
        for reply in arp_replies:
            if reply["dst_mac"] == request["src_mac"] and reply["flag"] == "unused":
                reply["flag"] = "used"
                pakety.append(request)
                pakety.append(reply)
                communication["number_comm"] = counter3
                communication["packets"] = pakety
                complete_comms.append(communication)
                pakety = []
                communication = {}
                counter3 += 1
                break
    for comm in complete_comms:
        for packet in comm["packets"]:
            if "operation" in packet:
                del packet["operation"]
            if packet in arp_requests:
                arp_requests.remove(packet)
            elif packet in arp_replies:
                arp_replies.remove(packet)
                del packet["flag"]

    for request in arp_requests:
        incomplete_comms.append(request)
    for reply in arp_replies:
        incomplete_comms.append(reply)
    complete_comms_clean = []
    incomplete_comms_clean = []
    for comm in complete_comms:
        cleaned_comm = comm.copy()
        cleaned_comm["packets"] = [packet.copy() for packet in comm['packets']]
        complete_comms_clean.append(cleaned_comm)
    komunikacia = {}
    komunikacia["number_comm"] = 1
    komunikacia["packets"] = []
    for comm in incomplete_comms:
        cleaned_comm = comm.copy()
        if "flag" in cleaned_comm:
            del cleaned_comm["flag"]
        if "operation" in cleaned_comm:
            del cleaned_comm["operation"]
        komunikacia["packets"].append(cleaned_comm)
    incomplete_comms_clean.append(komunikacia)
    output["name"] = "PKS2023/24"
    output["pcap_name"] = "arp.pcap"
    output["filter_name"] = "ARP"
    output["complete_comms"] = complete_comms_clean
    output["partial_comms"] = incomplete_comms_clean
    with open("output.yaml", "w") as file:
        ruamel.yaml.dump(output, file, Dumper=ruamel.yaml.RoundTripDumper)


