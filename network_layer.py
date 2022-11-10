import random, struct, socket, utils
from data_link_layer import EthernetSocket

# Function that gets the source IP address by connecting to another IP address 
# Citation: https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib
def get_source_ip_address():

    # Connect to an 8.8.8.8 address and unpack to get the source IP address 
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))

    return struct.unpack("!I", socket.inet_aton(s.getsockname()[0]))[0]

class IPSocket():

    def __init__(self):
        self.ID = random.randint(0, 65535)
        self.ethernet_socket = EthernetSocket()
        
        self.source_ip_address = get_source_ip_address()
        self.dest_ip_address = "" # no destination set yet 
        
    # Function that builds an IP Header from a packet and returns the IP Header in dict format
    def parse_packet_to_ip_header(self, packet):
        ip_header = {}

        packet = struct.unpack('!BBHHHBBHLL' , packet)
        ip_header["IHL"] = packet[0]
        ip_header["TOS"] = packet[1]
        ip_header["total_len"] = packet[2]
        ip_header["ID"] = packet[3]
        ip_header["frag_offset"] = packet[4]
        ip_header["TTL"] = packet[5]
        ip_header["protocol"] = packet[6]
        ip_header["checksum"] = packet[7]
        ip_header["source_ip_address"] = packet[8]
        ip_header["dest_ip_address"] = packet[9]

        return ip_header

    # Function that builds an IP Packet 
    def build_ip_packet(self, data):
        # all the fields that are contained in the ip header
        ip_version = 4 # assuming only using IPV4
        header_length = 5 # assuming no options
        TOS = 0
        length_of_ip_header = header_length * 4 
        total_len = length_of_ip_header + len(data) # length of IP header + length of data
        ID = self.ID
        flags = 0b000#[0, 0, 0] # the 3 flags for the ip header
        frag_offset = 0
        TTL = 255 # some number
        protocol = socket.IPPROTO_TCP

        ip_header = struct.pack(
            '!BBHHHBBHLL', 
            (ip_version << 4) + header_length, TOS, total_len,
            ID, (flags << 13) + frag_offset,
            TTL, protocol, 0,
            self.source_ip_address,
            self.dest_ip_address
        )

        ip_header = ip_header[:10] + struct.pack("H", utils.calculate_checksum(ip_header)) + ip_header[12:20]

        return ip_header + data

    # Function that sends data using IP
    def send_data(self, data):

        # build IP packet and update ID 
        ip_packet = self.build_ip_packet(data)
        self.ID = (self.ID + 1) % 65536

        # send the IP packet via the data link layer
        return self.ethernet_socket.send_data(ip_packet)

    # Function that receives data using IP
    def receive(self):
        received = None

        while received == None:
            # get packet from data link layer 
            ip_packet = self.ethernet_socket.receive()
            ip_header = ip_packet[:20]
            parsed_ip_header = self.parse_packet_to_ip_header(ip_header)

            # check if received IP packet is meant for this source and has the correct checksum
            if self.source_ip_address == parsed_ip_header["dest_ip_address"] and self.dest_ip_address == parsed_ip_header["source_ip_address"] and utils.calculate_checksum(ip_header) == 0:
                total_len = parsed_ip_header["total_len"]
                received = ip_packet[20: total_len]
        return received

	# Function that connects the source IP address to the destination/site needed via IP
    def connect(self, destination_ip):
        self.dest_ip_address = struct.unpack("!I", socket.inet_aton(destination_ip))[0]
        self.ethernet_socket.connect(self.source_ip_address)


    # Function to close the sockets
    def close(self):
        self.ethernet_socket.close_all()