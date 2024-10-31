import statistics

class Trace_statistics:
    def __init__(self, TCP_connections):
        self.TCP_connections = TCP_connections
        self.open_TCP_connections = 0
        self.pre_established_connections = 0
        self.reset_connections = 0
        self.complete_connections = 0
        self.complete = {}
        self.durations = []
        self.rtts = []
        self.packet_counts = []
        self.window_sizes = []

        
    def analyze_trace(self):
        for id,connection in self.TCP_connections.items():
            if(connection.completed):
                self.complete_connections+=1
                self.complete[connection.four_tuple] = connection
            if(connection.open_connection):
                self.open_TCP_connections+=1
            if(connection.pre_established_connection):
                self.pre_established_connections+=1
            if(connection.reset_flag):
                self.reset_connections+=1 
    

    def analyze_complete_connections(self):
        
        for id, connection in self.complete.items():
            #Create list of durations
            self.durations.append(connection.duration)
        
            #calculate RTT use top-down approach
            seq_to_timestamp = {}
            for packet in connection.packets:
                if packet.direction == 0: 
                    seq_to_timestamp[packet.seq_num + packet.segment_length] = packet.time_stamp
                elif packet.direction == 1 and packet.ack_num in seq_to_timestamp:
                    rtt = packet.time_stamp - seq_to_timestamp[packet.ack_num]
                    
                    if rtt > 0:  
                        self.rtts.append(rtt)
                        break
                    del seq_to_timestamp[packet.ack_num]

            #Get total packets and add to list
            self.packet_counts.append(len(connection.packets))

            #Put window sizes in a list
            for packet in connection.packets:
                self.window_sizes.append(packet.window_size)


    def print_output(self):
        count = 1
        print("Output for project 2\n")
        print(f"A) Total number of connections: {len(self.TCP_connections)}")
        print("_____________________________________________________________\n")
        print("B) Connection's details:\n")
        for id,connection in self.TCP_connections.items():
            print(f"Connection {count}")
            count+=1
            print(connection)
        print("_____________________________________________________________\n")
        print("C) General\n")
        print(f"Total number of complete TCP connections: {self.complete_connections}")
        print(f"Number of reset TCP connections: {self.reset_connections}")
        print(f"Number of TCP connections that were still open when trace capture ended: {self.open_TCP_connections}")
        print(f"The number of TCP connections established before the capture started: {self.pre_established_connections}\n")
        print("_____________________________________________________________\n")
        print("D) Complete TCP conenctions:\n")
        print(f"Minimum time duration: {min(self.durations):.6f} seconds")
        print(f"Mean time duration: {statistics.mean(self.durations):.6f} seconds")
        print(f"Maximum time duration: {max(self.durations):.6f} seconds\n")

        print(f"Minimum RTT value: {min(self.rtts):.6f}")
        print(f"Mean RTT value: {statistics.mean(self.rtts):.6f} ")
        print(f"Maximum RTT value: {max(self.rtts):.6f}\n")

        print(f"Minimum number of packets including both send/received: {min(self.packet_counts):.6f}")
        print(f"Mean number of packets including both send/received: {statistics.mean(self.packet_counts):.6f}")
        print(f"Maximum number of packets including both send/received: {max(self.packet_counts):.6f}\n")

        print(f"Minimum recieve window size including both send/received: {min(self.window_sizes):.6f} bytes")
        print(f"Mean recieve window size including both send/received: {statistics.mean(self.window_sizes):.6f} bytes")
        print(f"Maximum recieve window size including both send/received: {max(self.window_sizes):.6f} bytes\n")

        print("_____________________________________________________________\n")


                
    