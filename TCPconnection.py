class TCP_connection:

    def __init__(self,src_adr,src_port,dest_adr,dest_port):
        self.four_tuple = (src_adr,src_port,dest_adr,dest_port) # key for organizing the connections
        self.state = [0,0] # index 0 for SYN index 1 for FIN
        self.start_time = 0
        self.end_time = 0
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
        return (
            f"Connection: {self.four_tuple}\n"
            f"State: SYN {self.state[0]}, FIN {self.state[1]}\n"
            f"Start Time: {self.start_time}, End Time: {self.end_time}\n"
            f"Packets (Source -> Dest): {self.src_to_dest_count}, Data: {self.src_to_dest_data_count} bytes\n"
            f"Packets (Dest -> Source): {self.dest_to_src_count}, Data: {self.dest_to_src_data_count} bytes\n"
            f"Reset Flag Count: {self.reset_flag}\n"
            f"Completed: {self.completed}\n"
            f"Packets: {len(self.packets)} total packets\n"
            f"Pre-Established Connection: {self.pre_established_connection}\n"
            f"Open Connection: {self.open_connection}"
        )

    def analyze_connection(self):
        first_packet = True

        # Iterate over packets in this connection
        for  packet in self.packets:  # Iterating through packets in the connection

            # Handle the first packet of the connection
            if first_packet:
                if packet.flags.get("SYN", 0):
                    # Valid SYN packet, start connection
                    self.start_time = packet.time_stamp
                else:
                    # First packet is not SYN, mark as pre-established connection
                    self.pre_established_connection = True
                first_packet = False

            # Update connection state (checking for SYN and FIN flags)
            if packet.flags.get("SYN", 0):
                self.state[0] += 1  # SYN flag set

            if packet.flags.get("FIN", 0):
                self.state[1] += 1  # FIN flag set
                self.end_time = packet.time_stamp  # Mark end time when FIN is detected

            # Handle packet data transfer
            if packet.direction == 0:
                self.src_to_dest_count += 1
                self.src_to_dest_data_count += packet.segment_length
            else:
                self.dest_to_src_count += 1
                self.dest_to_src_data_count += packet.segment_length

            # Check for RST flag
            if packet.flags.get("RST", 0):
                self.reset_flag = True
                self.end_time = packet.time_stamp 

        # Now, implement the logic for checking connection completion
        # If we have SYN packets but no more data and FIN is present, mark as completed
        if self.state[0] > 0 and self.state[1] == 1:
            
            self.completed = True
            
        elif self.state[0] > 0 and self.state[1] == 2:
            self.completed = True

        # If the connection is not completed, mark as open
        if not self.completed:
            self.open_connection = True
        
                


