SAPtypes = {
    "00": "Null SAP",
    "02": "LLC Sublayer Management / Individual",
    "03": "LLC Sublayer Management / Group",
    "06": "IP",
    "0e": "PROWAY Network Management, Maintenance and Installation",
    "4e": "MMS",
    "5e": "ISI IP",
    "7e": "X.25 PLP",
    "8e": "PROWAY Active Station List Maintenance",
    "aa": "SNAP",
    "e0": "IPX",
    "f4": "LAN Management",
    "fe": "ISO Network Layer Protocols",
    "ff": "Global DSAP",
    "f0": "NETBIOS",
    "42": "STP",
}

PIDtypes = {
    "809b": "Appletalk",
    "2000": "CDP",
    "2004": "DTP",
    "010b": "PVSTP+"
}

ETHERtypes = {
    "0800": "IPv4",
    "86dd": "IPv6",
    "0806": "ARP",
    "88cc": "LLDP",
    "9000": "CTP loopback",
}

IPtypes = {
    "01": "ICMP",
    "02": "IGMP",
    "06": "TCP",
    "11": "UDP",
    "67": "PIM",
}

portsTCP = {
    "7": "echo",
    "19": "chargen",
    "20": "FTP data",
    "21": "FTP control",
    "22": "SSH",
    "23": "Telnet",
    "25": "SMTP",
    "53": "DNS",
    "79": "finger",
    "80": "HTTP",
    "110": "POP3",
    "111": "sunrpc",
    "119": "nntp",
    "139": "NetBIOS-ssn",
    "143": "IMAP",
    "179": "BGP",
    "389": "LDAP",
    "443": "HTTPS(SSL)",
    "445": "Microsoft-DS",
    "1080": "SOCKS",
}

portsUDP = {
    "7": "echo",
    "19": "chargen",
    "37": "time",
    "53": "DNS",
    "67": "DHCP",
    "68": "DHCP",
    "69": "TFTP",
    "137": "NetBIOS-ns",
    "138": "NetBIOS-dgm",
    "161": "SNMP",
    "162": "SNMP-trap",
    "500": "ISAKMP",
    "514": "syslog",
    "520": "RIP",
    "33434": "traceroute",
}