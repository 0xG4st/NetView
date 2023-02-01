import socket
import struct
import os

raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

if os.name == 'nt':
    raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
else:
    raw_socket.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)

raw_socket.bind(("0.0.0.0", 0))

while True:
    packet = raw_socket.recvfrom(65565)[0]

    ip_header = packet[0:20]
    ip_header = struct.unpack("!BBHHHBBHII", ip_header)

    ip_header_len = (ip_header[0] & 0xF) * 4

    protocol = ip_header[6]

    source_ip = socket.inet_ntoa(struct.pack("!I", ip_header[8]))
    dest_ip = socket.inet_ntoa(struct.pack("!I", ip_header[9]))

    if protocol == 6:
        tcp_header = packet[ip_header_len:ip_header_len+20]
        tcp_header = struct.unpack("!HHLLBBHHH", tcp_header)

        source_port = tcp_header[0]
        dest_port = tcp_header[1]

        data_offset = (tcp_header[4] >> 4) * 4

        flag_urg = (tcp_header[5] & 0x20) >> 5
        flag_ack = (tcp_header[5] & 0x10) >> 4
        flag_psh = (tcp_header[5] & 0x8) >> 3
        flag_rst = (tcp_header[5] & 0x4) >> 2
        flag_syn = (tcp_header[5] & 0x2) >> 1
        flag_fin = tcp_header[5] & 0x1

        print(f"{source_ip} -> ", dest_ip)
        print( "SOURCE    DEST  OFFSET  URG  ACK  PSH  RST  SYN  FIN")
        print(f"{str(source_port)}     {str(data_offset)}    {str(dest_port)}    {str(flag_urg)}    {str(flag_ack)}    {str(flag_psh)}    {str(flag_rst)}    {str(flag_syn)}    {str(flag_fin)}")
        print("-----------------------------------------------------------------------------------------------------")
    
    elif protocol == 17:
        udp_header = packet[ip_header_len:ip_header_len+8]
        udp_header = struct.unpack("!HHHH", udp_header)

        source_port = udp_header[0]
        dest_port = udp_header[1]

        print("Source port: " + str(source_port))
        print("Destination port: " + str(dest_port))

    elif protocol == 1:
        icmp_header = packet[ip_header_len:ip_header_len+4]
        icmp_header = struct.unpack("!BBH", icmp_header)

        icmp_type = icmp_header[0]
        icmp_code = icmp_header[1]

        print("ICMP type: " + str(icmp_type))
        print("ICMP code: " + str(icmp_code))
