from scapy.all import sniff, IP, TCP, UDP
log_file_path = 'packets.log'

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        log_entry = f"""
        Source IP: {ip_layer.src}
        Destination IP: {ip_layer.dst}
        Protocol: {ip_layer.proto}
        """
        if TCP in packet:
            tcp_layer = packet[TCP]
            log_entry += (
                f", TCP Packet: Source Port: {tcp_layer.sport}, "
                f"Destination Port: {tcp_layer.dport}"
            )
        elif UDP in packet:
            udp_layer = packet[UDP]
            log_entry += (
                f", UDP Packet: Source Port: {udp_layer.sport}, "
                f"Destination Port: {udp_layer.dport}"
            )

        print(log_entry)

        with open(log_file_path, 'a') as f:
            f.write(log_entry + '\n')

        if len(packet.payload) > 0:
            payload_data = bytes(packet.payload)
            print(f"Payload: {payload_data}")
            with open(log_file_path, 'a') as f:
                f.write(f"Payload: {payload_data}\n")

sniff(prn=packet_callback, store=0)  #use store=0 to not store packets in memory
