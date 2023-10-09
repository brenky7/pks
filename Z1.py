from collections import defaultdict
from ruamel.yaml.scalarstring import PreservedScalarString
from scapy.all import rdpcap
from MyDictionaries import SAPtypes, ETHERtypes, IPtypes, portsTCP, portsUDP
from MyDictionaries import PIDtypes
import ruamel.yaml

zaznam = "/Users/peterbrenkus/Desktop/skola/sem3/pks/Z1/pcap/trace-27.pcap"
packets = rdpcap(zaznam)
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
    manual_len = 0
    for layer in packet:
        manual_len += len(layer)
    packet_info["len_frame_pcap"] = len(packet)     #zapise dlzku paketu od pcap API
    packet_info["len_frame_medium"] = manual_len + 4    #zapise dlzku paketu manualne vypocitanu + 4B pre FCS
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
with open("mojPaket.yaml", "w") as yaml_file:

    ruamel.yaml.dump(fileOutput, yaml_file, Dumper=ruamel.yaml.RoundTripDumper)