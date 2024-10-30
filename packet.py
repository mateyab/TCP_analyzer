class Packet:
    def __init__(self):
        self.seq_num = None
        self.ack_num = None
        self.time_stamp = 0
        self.flags = {}
        self.segment_length = 0
        self.direction = 0 # zero for client to server, 1 for server to client
        self.window_size =0