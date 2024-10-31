class TCP_connection:

    def __init__(self,src_adr,src_port,dest_adr,dest_port):
        self.four_tuple = (src_adr,src_port,dest_adr,dest_port) # key for organizing the connections
        self.state = [0,0] # index 0 for SYN index 1 for FIN
        self.start_time = 0
        self.end_time = 0
        self.duration =0
        self.src_to_dest_count = 0
        self.dest_to_src_count = 0
        self.src_to_dest_data_count = 0
        self.dest_to_src_data_count = 0
        self.completed = False
        self.reset_flag = False
        self.packets = []
        self.pre_established_connection = False
        self.open_connection = False
    
    def __str__(self):
        connection_info = (
            f"Source Address: {self.four_tuple[0]}\n"
            f"Destination Address: {self.four_tuple[2]}\n"
            f"Source Port: {self.four_tuple[1]}\n"
            f"Destination Port: {self.four_tuple[3]}\n"
            f"Status: S{self.state[0]}F{self.state[1]}{'/R' if self.reset_flag else ''}\n"

        )

        if self.completed:
            connection_info += (
                f"Start Time: {self.start_time:.6f} seconds\n"
                f"End Time: {self.end_time:.6f} seconds\n"
                f"Duration: {self.duration:.6f} seconds\n"
                f"Number of packets sent from Source to Destination: {self.src_to_dest_count}\n"
                f"Number of packets sent from Destination to Source: {self.dest_to_src_count}\n"
                f"Total number of packets: {len(self.packets)}\n"
                f"Number of data bytes sent from Source to Destination: {self.src_to_dest_data_count} bytes\n"
                f"Number of data bytes sent from Destination to Source: {self.dest_to_src_data_count} bytes\n"
                f"Total number of data bytes: {self.src_to_dest_data_count + self.dest_to_src_data_count} bytes\n"
            )

        connection_info += "END\n"
        connection_info += "+++++++++++++++++++++++++++++++++\n"

        return connection_info

    def analyze_connection(self):
        first_packet = True

        # Iterate over packets in this connection
        for  packet in self.packets: 

            # Handle the first packet of the connection
            if first_packet:
                if packet.flags.get("SYN", 0):
                    # Valid SYN packet, start connection
                    self.start_time = float(packet.time_stamp)
                else:
                    # First packet is not SYN, mark as pre-established connection
                    self.pre_established_connection = True
                first_packet = False

            # Update connection state (checking for SYN and FIN flags)
            if packet.flags.get("SYN", 0):
                self.state[0] += 1  # SYN flag set

            if packet.flags.get("FIN", 0):
                self.state[1] += 1  # FIN flag set
                self.end_time = float(packet.time_stamp)  # Mark end time when FIN is detected
            # Collect packet segment lengths
            if packet.direction == 0:
                self.src_to_dest_count += 1
                self.src_to_dest_data_count += packet.segment_length
            else:
                self.dest_to_src_count += 1
                self.dest_to_src_data_count += packet.segment_length

            # Check for RST flag
            if packet.flags.get("RST", 0):
                self.reset_flag = True
                if(self.state[1] == 0 ):
                    self.end_time = float(packet.time_stamp) 
                    
        
        # logic for checking connection completion
        # If we have SYN packets but no more data and FIN is present, mark as completed
        if self.state[0] > 0 and self.state[1] == 1:
            
            self.completed = True
            
        elif self.state[0] > 0 and self.state[1] == 2:
            self.completed = True

        # If the connection is not completed, mark as open
        if not self.completed:
            self.open_connection = True

        #Calculate duration
        self.duration = self.end_time - self.start_time 
        
        
                


