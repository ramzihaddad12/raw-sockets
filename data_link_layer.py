import struct, subprocess, socket, binascii
from constants import ETH_P_ALL, ETH_P_ARP, ETH_P_IP, MIN_ETHERNET_SIZE

# Function that gets the interface of the local machine using the ifconfig command
def get_interface():
	output = subprocess.getoutput("ifconfig ")
	# Parse the command output to find the interface
	return output[:6]

# Function that gets the source MAC Address using the ifconfig command
def get_source_mac_address(interface):
		mac = subprocess.getoutput("ifconfig " + interface + " | grep ether")
		# Parse the command output to find the source mac address belonging to the interface
		index = mac.index('ether')
		mac = mac[index + len('ether '): index + len('ether ') + 17]
		if len(mac) == 17:
			return binascii.unhexlify(mac.replace(':', ''))

# Citation: stackoverflow.com/questions/2761829/python-get-default-gateway-for-a-local-interface-ip-address-in-linux
def get_default_gateway(interface):
	f = open("/proc/net/route")

	for line in f:
		fields = line.strip().split()
		if fields[0] == interface and fields[1] == '00000000' and int(fields[3], 16) & 2:
			return fields[2]

			
class EthernetSocket():
	
	def __init__(self):
		# instantiate sender and receiver sockets
		self.socket_sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
		self.socket_recver = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))

		self.interface = get_interface()
		self.source_mac =  get_source_mac_address(self.interface)

		# destination MAC address initially is the broadcast MAC
		self.dest_mac = b"\xff\xff\xff\xff\xff\xff"

	# Citation: https://en.wikipedia.org/wiki/Address_Resolution_Protocol
	# Function that builds an ARP Packet from scratch and returns the ARP packet in dict format
	def build_arp_packet_from_scratch(self):
		arp_packet = {}

		arp_packet["HTYPE"]= 1 
		arp_packet["PTYPE"] = ETH_P_IP 
		arp_packet["HLEN"] = 6 
		arp_packet["PLEN"] = 4 
		arp_packet["OPER"] = 1 # request operation --> OPER = 1
		arp_packet["SHA"] = b"\x00\x00\x00\x00\x00\x00" 
		arp_packet["SPA"] = 0 
		arp_packet["THA"] = b"\x00\x00\x00\x00\x00\x00" 
		arp_packet["TPA"] = 0 

		return arp_packet
	
	# Function that builds an ARP Packet from a packet and returns the ARPpacket in dict format
	def parse_packet_to_arp_packet(self, packet):
		arp_packet = {}

		# 8 - 14 & 18 - 24 not needed to unpack since they correspond to the sender & receiver hardware addresses
		data = struct.unpack("!HHBBHLL", packet[:8] + packet[14:18] + packet[24:28])

		arp_packet["HTYPE"]= data[0]
		arp_packet["PTYPE"] = data[1] 
		arp_packet["HLEN"] = data[2]
		arp_packet["PLEN"] = data[3]
		arp_packet["OPER"] = data[4]
		arp_packet["SHA"] = packet[8:14] # 6 bytes
		arp_packet["SPA"] = data[5]
		arp_packet["THA"] = packet[18:24] # 6 bytes
		arp_packet["TPA"] = data[6] 

		return arp_packet
	
	# Function that sends data using ethernet
	def send_data(self, data, ether_type = ETH_P_IP):
		# build ethernet header 
		ethernet_header = struct.pack("!6s6sH", self.dest_mac, self.source_mac, ether_type)
		print("SENDING: " )
		print(self.source_mac)
		print(ethernet_header)
		print(data)
		if len(data) >= MIN_ETHERNET_SIZE:
			self.socket_sender.sendto(ethernet_header + data, (self.interface,0))

		# if data is shorter than MIN_ETHERNET_SIZE then we need to prepend 0's before sending the data via ethernet 
		else:
			data = data + str.encode("\x00") * (MIN_ETHERNET_SIZE - len(data))
			self.socket_sender.sendto(ethernet_header + data, (self.interface,0))

	# Function that receives data using ethernet
	def receive(self, ether_type = ETH_P_IP):
		received = None

		# while the data is not intended to the source address 
		while received == None:
			received_data = self.socket_recver.recv(65536)

			packet_dest_mac = struct.unpack("!6s6sH", received_data[:14])[0]
			packet_source_mac = struct.unpack("!6s6sH", received_data[:14])[1]
			packet_ether_type = struct.unpack("!6s6sH", received_data[:14])[2]

			# print("packet_dest_mac: {}".format(packet_dest_mac))
			# print("self.source_mac: {}".format(self.source_mac))	

			# check if the packet corresponds to the source MAC address (check if the packet is meant to the local machine)
			if packet_dest_mac != self.source_mac or ether_type != packet_ether_type :
				received = None

			else:
				if ether_type != ETH_P_ARP and packet_source_mac != self.dest_mac:
					received = None
				else:
					received = received_data[14:]

		return received

	# Function that connects the source IP address to the destination/site needed via ethernet
	def connect(self, source_ip_address):
		# build and send ARP packet to the target 
		request_arp_packet = self.build_arp_packet_from_scratch()

		request_arp_packet["TPA"] = socket.htonl(int(str(get_default_gateway(self.interface)), 16))
		request_arp_packet["SHA"] = self.source_mac
		request_arp_packet["SPA"] = source_ip_address

		data_to_send = struct.pack("!HHBBH6sL6sL", request_arp_packet["HTYPE"], request_arp_packet["PTYPE"], request_arp_packet["HLEN"],
									request_arp_packet["PLEN"], request_arp_packet["OPER"],request_arp_packet["SHA"], request_arp_packet["SPA"],
									request_arp_packet["THA"], request_arp_packet["TPA"])

		self.send_data(data_to_send, ether_type = ETH_P_ARP)

		# get response back 
		response = None

		while response == None:

			packet = self.receive(ether_type = ETH_P_ARP)
			arp_packet = self.parse_packet_to_arp_packet(packet)
			
			# check if received ARP packet is meant for this source and that it is a response packet (OPER = 2)
			if source_ip_address == arp_packet["TPA"] and self.source_mac == arp_packet["THA"] and arp_packet["OPER"] == 2:
				response = arp_packet
				break
		
		# once ARP packet is received, we now know the destination MAC address and we can change it from the broadcast MAC to the needed one
		self.dest_mac = response["SHA"]
		print("self.dest_mac: {}".format(self.dest_mac))
	
	# Function to close sender & receiving sockets
	def close_all(self):
		self.socket_recver.close()
		self.socket_sender.close()
