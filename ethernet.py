import struct, subprocess
import socket
import uuid
from uuid import getnode as get_mac
import fcntl

def prettify(mac_string):
    return ':'.join('%02x' % (b) for b in mac_string)
def get_mac_address(iface='enp0s3'):
		"""Return the MAC address of the localhost
		:param iface: 
		"""
		mac = subprocess.getoutput("ifconfig " + iface + " | grep ether") #HWaddr | awk '{ print $5 }'")
		index = mac.index('ether')
		mac = mac[index + len('ether '): index + len('ether ') + 17] #
		print(mac)
		if len(mac) == 17:
			return mac.replace(':', '')
def get_mac_addr(ifname='enp0s3'):
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', bytes(ifname[:15], 'utf-8')))
  return ''.join(['%02x:' % b for b in info[18:24]])[:-1]
			
class EthernetSocket(object):
	#Constants from sys/ethernet.h
	ETH_P_IP = 0x0800
	ETH_P_ARP = 0x0806
	ETH_P_ALL = 0x0003

	

	def __init__(self):
		self.broadcast_mac = b"\xff\xff\xff\xff\xff\xff"
		self.my_mac = b"\x08\x00\x27\x3f\x8e\x5a"#"\x08\x00'?\x8eZ"
		print('get_mac_addr()', get_mac_addr())
		
		#We can only send to the broadcast mac until we know where the gateway is
		self.dest_mac = self.broadcast_mac
		print('uuid.getnode(): ',  struct.pack("!Q", uuid.getnode()))
		self.src_mac =  self.my_mac#struct.pack("!Q", uuid.getnode())[2:] #get_mac_address()#
		print('self.dest_mac: ', self.dest_mac)
		print('self.src_mac: ', self.src_mac) #08:00:27:3f:8e:5a
		print(get_mac())

		#For my arch machine, use eth0 for everything else
		#self.interface = "ens33"
		self.interface = "enp0s3"#"eth0"

		#Construct sockets. Due to linux oddities, there needs to be a separate socket for receiving and sending
		self.send_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(EthernetSocket.ETH_P_ALL))
		self.recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(EthernetSocket.ETH_P_ALL))
		return

	#Construct ethernet frame header and send data
	def send(self, data, eth_type = 0x0800):
		print(self.dest_mac, self.src_mac, eth_type)
		# print(str.encode(self.dest_mac), str.encode(self.src_mac), eth_type)
		# print(type(self.dest_mac), type(self.src_mac), type(eth_type))
		header = struct.pack("!6s6sH", self.dest_mac, self.src_mac, eth_type)#str.encode(
		#pack to minimum length
		if len(data) < 46:
			print(type(data))
			data +=  str.encode("\x00")*(46 - len(data))

		packet = header + data
		print('packet: ', packet)

		self.send_sock.sendto(packet, (self.interface,0))
		print("SENTTTT")
		return

	def recv(self, bufsize, eth_type = 0x0800):
		data = None

		while data == None:
			packet = self.recv_sock.recv(65536)
			#print(packet)
			if EthernetSocket.isValid(self, packet, eth_type):
				data = packet[14:]
				print("************")
				print(data)
				break

		return data

    #Checks if the received packet is destined for us
	def isValid(self, packet, desired_type):
		print('&&&&&&&&&&&&&&')
		print(packet)
		unpacked = struct.unpack("!6s6sH", packet[:14])
		dest_mac = unpacked[0]
		src_mac = unpacked[1]
		eth_type = unpacked[2]
		print('^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^')
		print('dest_mac: ', dest_mac)
		# print('self.src_mac: ', str.encode(self.src_mac))
		print(prettify(dest_mac))
		print("08:00:27:3f:8e:5a")
		# print(prettify(str.encode(self.my_mac)))
		print('self.dest_mac: ', "\xff\xff\xff\xff\xff\xff")
		print('src_mac: ', src_mac)
		print('eth_type: ', eth_type)
		print('desired_type: ', desired_type)
		print('EthernetSocket.ETH_P_ARP: ', EthernetSocket.ETH_P_ARP)

		if eth_type != desired_type:
			print("HEREEE1")
			return False

		if "08:00:27:3f:8e:5a" != prettify(dest_mac):#and "c3:bf:c3:bf:c3:bf" != prettify(dest_mac):
			print("HEREEE2")
			return False

		#If we are still arping, we don't have a dest_mac set yet
		if desired_type != EthernetSocket.ETH_P_ARP:
			if self.dest_mac != src_mac:
				print("HEREEE3")
				return False


		return True

    #from stackoverflow.com/questions/2761829/python-get-default-gateway-for-a-local-interface-ip-address-in-linux
    #Gets the address of the default gateway on our interface
	def get_default_gateway(self):
		f = open("/proc/net/route")

		for line in f:
			print(line)
			fields = line.strip().split()
			if fields[0] != self.interface or fields[1] != '00000000' or not int(fields[3], 16) & 2:
				continue;

			return fields[2]

    #arps to find the gateway mac address so we can send packets
	def connect(self, src_ip):
		print("_____CONNECTION START_____")
		#arp to find gateway

		request = ArpPacket()
		request.SHA = self.src_mac
		request.SPA = src_ip
		print(type(self.get_default_gateway()))
		print(self.get_default_gateway())
		request.TPA = socket.htonl(int(str(self.get_default_gateway()), 16))


		EthernetSocket.send(self, request.toData(), eth_type = EthernetSocket.ETH_P_ARP)

		reply = None
		#wait for ARP reply to our request
		while reply == None:
			print("IN LOOP")
			packet = EthernetSocket.recv(self, 1500, eth_type = EthernetSocket.ETH_P_ARP)
			packet = ArpPacket(packet)
			if packet.operation == 2 and packet.THA == self.src_mac and packet.TPA == src_ip:
				reply = packet
				break

		#Grab mac address of gateway from the reply packet
		self.dest_mac = reply.SHA

		print("_____CONNECTION DONE_____")

		return


	#Close sockets
	def close(self):
		self.recv_sock.close()
		self.send_sock.close()
		return

class ArpPacket(object):

	def __init__(self, data = None):
		#Create a request
		if data == None:
			self.HTYPE = 1 #specify ethernet protocol
			self.PTYPE = EthernetSocket.ETH_P_IP #type of protocol we want to find out about
			self.HLEN = 6 #length of ethernet address
			self.PLEN = 4 #length of ip address
			self.operation = 1 #1 for request, 2 for reply
			self.SHA = b"\x00\x00\x00\x00\x00\x00" #sender hardware address
			self.SPA = 0 #ip addr as int
			self.THA = b"\x00\x00\x00\x00\x00\x00" #target hardware address, doesn't matter for request
			self.TPA = 0 #target protocol address, address to lookup in request
		else:
			unpacked = struct.unpack("!HHBBHLL", data[:8] + data[14:18] + data[24:28])
			self.HTYPE = unpacked[0] #specify ethernet protocol
			self.PTYPE = unpacked[1] #type of protocol we want to find out about
			self.HLEN = unpacked[2] #length of ethernet address
			self.PLEN = unpacked[3] #length of ip address
			self.operation = unpacked[4] #1 for request, 2 for reply, should be 2
			self.SHA = data[8:14] #Address of host we are looking for
			self.SPA = unpacked[5] #ip of who sent the reply
			self.THA = data[18:24] #Address of intended receiver, should be us
			self.TPA = unpacked[6] #ip of intended receiver, should be us

	def toData(self):
	#data = struct.pack("!HHBBH", self.HTYPE, self.PTYPE, self.HLEN, self.PLEN, self.operation)
	#data += self.SHA
	#data += struct.pack("!L", self.SPA)
	#data += self.THA
	#data += struct.pack("!L", self.TPA)
		print(("!HHBBH6sL6sL", self.HTYPE, self.PTYPE, self.HLEN, self.PLEN, self.operation,
				self.SHA, self.SPA, self.THA, self.TPA))
		print(type(self.SHA))
		print(type(self.THA))
		data = struct.pack("!HHBBH6sL6sL", self.HTYPE, self.PTYPE, self.HLEN, self.PLEN, self.operation,
				self.SHA, self.SPA, self.THA, self.TPA)

		return data