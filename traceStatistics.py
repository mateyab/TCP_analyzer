class Trace_statistics:
    def __init__(self, TCP_connections):
        self.TCP_connections = TCP_connections
        self.open_TCP_connections = 0
        self.pre_established_connections = 0
        self.reset_connections = 0
        self.complete_connections = 0

        
    def analyze_trace(self):
        for id,connection in self.TCP_connections.items():
            if(connection.completed):
                self.complete_connections+=1
            if(connection.open_connection):
                self.open_TCP_connections+=1
            if(connection.pre_established_connection):
                self.pre_established_connections+=1
            if(connection.reset_flag):
                self.reset_connections+=1 
        print(self.open_TCP_connections)
        print(self.pre_established_connections)
        print(self.reset_connections)
        print(self.complete_connections)
        




