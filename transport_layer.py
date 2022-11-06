import random, constants, struct, socket, utils, threading, network_layer


''' from: https://www.binarytides.com/raw-sockets-c-code-linux/
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
'''
class TCPPacket:
    def __init__(self, src_port, dst_port, seq_no, ack_no, window, ack, syn, fin, data):
        # set attributes for class based on TCP packet above
        self.source_port = src_port
        self.destination_port = dst_port
        self.sequence_number = seq_no
        self.ack_number = ack_no
        self.data_offset = 5
        self.window = window
        
        # when set, treat data as priority over other data
        self.urg = 0
        # used for acknowledgement
        self.ack = ack
        # push function - transmit data immediately (don't fill full tcp segment)
        self.psh = 0
        # reset connection - when set, terminate connection immediately
        self.rst = 0
        # used in 3-way handshake
        self.syn = syn
        # end TCP connection
        self.fin = fin

        # advertised window
        self.window = constants.MAX_INT16
        # checksum for TCP header
        self.checksum = 0
        # when URG flag set, indicate where data ends
        self.urgent_pointer = 0
        self.options = b''
        self.data = data


    # encode packed header
    def encode_header(self):
        # encode flags with bit shift
        flags = \
            (self.urg << 5) + \
            (self.ack << 4) + \
            (self.psh << 3) + \
            (self.rst << 2) + \
            (self.syn << 1) + \
            self.fin
        
        # return packed header
        return struct.pack('!HHLLBBH',
            self.source_port,
            self.destination_port,
            self.sequence_number,
            self.ack_number,
            (self.data_offset << 4),
            flags,
            self.window
        ) + \
            struct.pack('H', self.checksum) + \
            struct.pack('!H', self.urgent_pointer)


    # get the checksum for this packet
    def get_checksum(self, source_ip, dest_ip):
        checksumless_header = self.encode_header()

        # 8 bits of 0s
        reserved = 0
        # protocol field of IP header
        ip_protocol = socket.IPPROTO_TCP
        # length of TCP segment
        tcp_length = len(checksumless_header) + len(self.data)

        # static parts of IP header (https://www.baeldung.com/cs/pseudo-header-tcp)
        pseudo_header = struct.pack('!LLBBH',
            source_ip,
            dest_ip,
            reserved,
            ip_protocol,
            tcp_length
        )

        # construct packet with pseudo header to get checksum
        packet = pseudo_header + checksumless_header
        if len(self.data) > 0:
            packet += self.data

        return utils.calculate_checksum(packet)


    # create packet with checksum
    def build(self, source_ip, dest_ip):
        self.checksum = self.get_checksum(source_ip, dest_ip)
        
        packet = self.encode_header()
        if self.data > 0:
            packet += self.data

        return packet


    # validate port
    def is_valid_port(self, dst_port):
        return self.destination_port == dst_port


    def unpack(self, packet):
        unpacked_packet = struct.unpack('!HHLLBBHHH', packet[:16])
        unpacked_checksum = struct.unpack('H', packet[16:18])
        data = packet[20:]

        source_ip = unpacked_packet[0]
        dest_ip = unpacked_packet[1]
        sequence_number = unpacked_packet[2]
        ack_number = unpacked_packet[3]
        # don't need data offset
        window = unpacked_packet[6]
        # don't need urgent_pointer

        # don't need urg, psh, rst
        flags = unpacked_packet[5]
        ack = ((flags & 16) >> 4)
        syn = ((flags & 2) >> 1)
        fin = flags & 1

        packet = TCPPacket(source_ip, dest_ip, sequence_number, ack_number, window, ack, syn, fin, data)
        packet.checksum = unpacked_checksum[0]

        return packet


# Keep track of in-flight packets
class TCPPacketInFlight():
    def __init__(self, packet, ack_number):
        self.packet = packet
        self.ack_number = ack_number
        self.timer = threading.Timer(constants.TIMEOUT_SECONDS, TransportSocket.resend_packet, [self])


# Custom TCP Socket
class TransportSocket:
    def __init__(self):
        self.ip_socket = network_layer.IPSocket()
        self.source_port = random.randint(0, constants.MAX_INT16)
        self.destination_port = 0
        self.connected = False
        self.finned = False
        self.fin_received = False
        self.cwnd = 1
        self.sequence_number = random.randint(0, constants.MAX_INT32)
        self.ack_number = 0
        self.inflight_packets = []
        self.receive_buffer = []
        

    # connect with host and port
    def connect(self, socket_addr):
        host, self.dest_port = socket_addr
        self.ip_socket.connect(socket.gethostbyname(host))
        self.send_syn()


    # if packet times out, resend it and reset cwnd
    def resend_packet(self, packet):
        self.cwnd = 1
        self.packets_in_flight.remove(packet)
        self.send_packet(packet.packet)


    # receive all data until fin observed
    def receive_all(self):
        message = ''
        while not self.fin_received and not self.finned:
            received = self.receive()
            if received:
                message += received.decode('utf-8')
        return message


    # receive a single packet, filter out packets not destined to us
    def receive(self):
        received = self.ip_socket.receive()
        if self.dest_port == self.source_port:
            return self.parse_packet(received)
        return None

    
    # parse packet for flags, return data if not fin
    def parse_packet(self, data):
        packet = TCPPacket.unpack(data)

        if not self.connected:
            self.force_connect(packet)
            return

        # if already received packet or packet outside of window
        if self.ack_number > packet.sequence_number or \
            packet.sequence_number > self.ack_number + constants.MAX_INT16:
            return

        # unexpected packet will be added to buffer 
        if self.ack_number < packet.sequence_number:
            self.receive_buffer.append(packet)
            self.receive_buffer.sort(key = lambda packet: (self.get_next_sequence_no(packet.sequence_number, -self.ack_number)))

        self.handle_flagged_packets(packet)
        if not self.fin_received:
            return self.read_packet(packet)


    # if connection not initialized
    def force_connect(self, packet):
        self.ack_number = self.get_next_sequence_no(packet.sequence_number, 1)
        self.sequence_number += 1
        self.send_ack()
        self.inflight_packets.pop()
        self.increase_cwnd()
        self.connected = True
    

    # increment congestion window, up to 1000
    def increase_cwnd(self):
        self.cwnd = min(self.cwnd + 1, constants.MAX_CWND)


    # handle case where ack flag set
    def check_ack(self, packet):
        # free window space from ACKed packets, increment cwnd
        if packet.ack == 1:
            num_acked = 0
            for packet_infl in self.inflight_packets:
                if packet_infl.ack_number <= packet.ack_number:
                    self.sequence_number += len(packet_infl.packet.data)
                    num_acked += 1
                else:
                    break

            self.inflight_packets = self.inflight_packets[num_acked:]
            self.increase_cwnd()


    # close connection if fin flag set
    def check_fin(self, packet, incr_ack = True):
        if packet.fin == 1:
            self.fin_received = True
            if incr_ack:
                self.ack_number += 1
            self.send_ack()
            self.close()


    # Given non-fin, in-order packet, update state and read info
    def read_packet(self, packet):
        self.ack_number += len(packet.data)
        data = packet.data

        for packet_buff in self.receive_buffer:
            if packet_buff.sequence_number == self.ack_number:
                data += packet_buff.data
                self.ack_number += len(packet.data)
                self.receive_buffer.remove(packet_buff)

                self.check_fin(packet_buff)
                if self.fin_received:
                    return data
            break # why?

        self.send_ack()
        return data    


    # send the given packet
    def send(self, packet, append_window = True):
        data_len = 1 if packet.syn == 1 or packet.fin == 1 else len(packet.data)
        ack_number = self.get_next_sequence_no(packet.sequence_number, data_len)

        inflight_packet = TCPPacketInFlight(packet, ack_number)

        if append_window:
            self.inflight_packets.append(inflight_packet)

        data = inflight_packet.packet.build(
            self.ip_socket.source_ip_address,
            self.ip_socket.dest_ip_address
        )

        self.ip_socket.send_data(data)
        

    # get next sequence number with wrap-around
    def get_next_sequence_no(self, sequence_number, data_len):
        return (sequence_number + data_len) % constants.MAX_INT32

    
    # build basic TCP packet without data
    def basic_tcppacket_builder(self, ack, syn, fin):
        return TCPPacket(
            self.source_port, 
            self.dest_port,
            self.sequence_number,
            self.ack_number,
            constants.MAX_INT16,
            ack,
            syn,
            fin,
            ''
        )


    # send a syn packet and get response
    def send_syn(self):
        syn_packet = self.basic_tcppacket_builder(0, 1, 0)
        self.send(syn_packet)

        while not self.connected:
            self.receive()

    
    # send a fin packet
    def send_fin(self):
        fin_packet = self.basic_tcppacket_builder(1, 0, 1)
        self.send(fin_packet)


    # send an ack packet
    def send_ack(self):
        ack_packet = self.basic_tcppacket_builder(1, 0, 0)
        self.send(ack_packet, False)

    
    # close connection with fin
    def close(self):
        if not self.finned:
            self.send_fin()
            self.finned = True

        while not self.fin_received:
            # drain queue, throw away data
            self.receive()

        self.ip_socket.close()
        return
    


    