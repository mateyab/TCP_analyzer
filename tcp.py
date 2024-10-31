from packet import Packet
from TCPconnection import TCP_connection
from traceStatistics import Trace_statistics
import struct
import sys

def parse_file(file, TCP_connections):
    with open(file, "rb") as f:
        global_header = f.read(24)

        capture_start_time = None

        while True:
            packet_header = f.read(16)  # Each packet header is 16 bytes long
            if len(packet_header) < 16:
                break  # End of file

            # Unpack the packet header
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack('IIII', packet_header)

            # Read the packet data
            packet_data = f.read(incl_len)

            if capture_start_time is None:
                capture_start_time = float(ts_sec) + ts_usec / 1_000_000

            packet_time = float(ts_sec) + ts_usec / 1_000_000 - capture_start_time

            packet = Packet() #new packet
            packet.time_stamp = packet_time
       
            # first 14 bytes is the ethernet header 
            #then get the ipv4 header, the 5th bit plus 4 is the IHL to determine the header length then skip this and get to the TCP header
            # then extract the first 20 bytes to get info needed
            ethernet_header = packet_data[:14]
            eth_fields = struct.unpack('!6s6sH', ethernet_header)
            ethertype = eth_fields[2]
            if ethertype != 0x0800:  # Only handle IPv4 (Ethertype 0x0800)
                return

            #Parse the IPv4 header (starts after 14 bytes)
            ipv4_header = packet_data[14:34]  # First 20 bytes of the IPv4 header
            ipv4_fields = struct.unpack('!BBHHHBBH4s4s', ipv4_header)
            total_length = ipv4_fields[2]
            version_ihl = ipv4_fields[0]
            ihl = (version_ihl & 0x0F) * 4  # IHL is in 32-bit words, multiply by 4 for bytes
            
            protocol = ipv4_fields[6]
            src_ip = '.'.join(map(str, ipv4_fields[8]))
            dest_ip = '.'.join(map(str, ipv4_fields[9]))
            if(protocol != 6):
                continue # not a TCP
            

            #Skip the rest of the IPv4 header if IHL > 20 bytes
            ipv4_end = 14 + ihl  # Calculate the end of the IPv4 header
            tcp_header = packet_data[ipv4_end:ipv4_end+20]  # Next 20 bytes for the TCP header
            
            # 4. Parse the TCP header (20 bytes)
            tcp_fields = struct.unpack('!HHLLBBHHH', tcp_header)
            src_port = tcp_fields[0]
            dest_port = tcp_fields[1]
            seq_num = tcp_fields[2]
            ack_num = tcp_fields[3]
            data_offset_reserved_flags = tcp_fields[4]
            tcp_header_length = (data_offset_reserved_flags >> 4) * 4  # TCP header length in bytes
            window_size = tcp_fields[6]

            packet.seq_num = seq_num
            
            packet.ack_num = ack_num
            packet.window_size = window_size

            flags = tcp_fields[5] & 0x3F 

            fin_flag = 1 if flags & 0x01 else 0
            syn_flag = 1 if flags & 0x02 else 0
            rst_flag = 1 if flags & 0x04 else 0
            psh_flag = 1 if flags & 0x08 else 0
            ack_flag = 1 if flags & 0x10 else 0
            urg_flag = 1 if flags & 0x20 else 0

            # Create the flags dictionary with the updated values
            packet.flags = {
                "FIN": fin_flag,
                "SYN": syn_flag,
                "RST": rst_flag,
                "PSH": psh_flag,
                "ACK": ack_flag,
                "URG": urg_flag
            }
            
            tcp_segment_length = total_length - ihl - tcp_header_length
            packet.segment_length = tcp_segment_length

            four_tuple = (src_ip,src_port,dest_ip,dest_port)
            four_tuple_reverse = (dest_ip,dest_port,src_ip,src_port)

            # Check if the connection already exists, add packets to the list
            if four_tuple in TCP_connections:
                connection = TCP_connections[four_tuple]
                packet.direction = 0  # Client (src) to server (dest)
                connection.packets.append(packet)  # Add packet to the list
                
            elif four_tuple_reverse in TCP_connections:
                connection = TCP_connections[four_tuple_reverse]
                packet.direction = 1  # Server (dest) to client (src)
                connection.packets.append(packet)  # Add packet to the list

            else:
                # Create a new connection if it doesn't exist
                new_connection = TCP_connection(src_ip, src_port, dest_ip, dest_port)
                new_connection.packets.append(packet)  # Add the first packet to the list
                TCP_connections[four_tuple] = new_connection
                


def main():
    '''
    Main entry point of the program.
    Processes a .cap file by creating a dictionary of each TCP connection,
    analyzing each connection, and printing the output.
    '''
    TCP_connections = {}
    
    # Ensure a capture file path is provided as a command-line argument
    if len(sys.argv) < 2:
        print("Please enter a .cap file")
        sys.exit(1)
    
    # Parse the capture file and populate the TCP_connections dictionary
    cap_file_path = sys.argv[1]
    parse_file(cap_file_path, TCP_connections)

    # Analyze each individual TCP connection
    for connection_id, connection in TCP_connections.items():
        connection.analyze_connection()

    # Analyze the entire trace based on connection data
    trace_statistics = Trace_statistics(TCP_connections)
    trace_statistics.analyze_trace()
    trace_statistics.analyze_complete_connections()
    
    # Print the analysis results
    trace_statistics.print_output()
    
    
if __name__ == "__main__":
    main()


