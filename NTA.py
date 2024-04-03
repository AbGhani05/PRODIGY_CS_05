from scapy.all import sniff ,IP, Raw

# Defining a function to process captured packets
def process_packet(packet):
    # Extracting relevant information from the packet
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = packet[IP].proto
    payload_data = packet[Raw].load if Raw in packet else ""

    # Displaying the extracted information
    print(f"Source IP: {src_ip}")
    print(f"Destination IP: {dst_ip}")
    print(f"Protocol: {protocol}")
    print(f"Payload Data: {payload_data}\n")

# Starting sniffing packets on the network interface
print("Packet Sniffer started...\n")
sniff(filter="", prn=process_packet, store=0)
