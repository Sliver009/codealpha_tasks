from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import socket
from datetime import datetime


def get_service_name(port, protocol):
    try:
        name = socket.getservbyport(port, protocol)
    except Exception as e:
        name = "unknown"
    return name


def show_packet_details(packet):
    if packet.haslayer(IP):
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        protocol_type = "-"
        source_port = "-"
        destination_port = "-"
        source_service_name = "-"
        destination_service_name = "-"

        if packet.haslayer(TCP):
            protocol_type = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport
            source_service_name = get_service_name(source_port, 'tcp')
            destination_service_name = get_service_name(
                destination_port, 'tcp'
            )
        elif packet.haslayer(UDP):
            protocol_type = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport
            source_service_name = get_service_name(source_port, 'udp')
            destination_service_name = get_service_name(
                destination_port, 'udp'
            )
        elif packet.haslayer(ICMP):
            protocol_type = "ICMP"
        else:
            protocol_type = "Other"

        current_time = datetime.now().strftime('%H:%M:%S')
        print(
            f"{current_time:8} | {protocol_type:8} | "
            f"{source_ip}:{str(source_port):<9} "
            f"{destination_ip}:{str(destination_port):<9} | "
            f"{source_service_name:<12} {destination_service_name:<12}"
        )

        if packet.haslayer(Raw):
            data = packet[Raw].load
            try:
                data_text = data[:30].decode(errors='replace')
            except Exception:
                data_text = str(data[:30])
            print(f"(Payload): {data_text}")
        print('-' * 110)


print('-' * 110)
print(f"| {'Time':<8} | {'Protocol':<8} | {'Source':<22}"
      f" {'Destination':<22} | {'Service Name':<27} |")
print('-' * 110)

sniff(prn=show_packet_details, store=0, count=50)
