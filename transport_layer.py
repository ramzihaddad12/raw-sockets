import constants, struct, socket, utils, random, threading
from network_layer import IPSocket

class TCPSegment:
    def __init__(self, src_port, dst_port, seq_no, ack_no, window, ack, syn, fin, data):
        # set attributes for class based on TCP headers
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
        self.data = data


    # create TCP segment with checksum
    def assemble(self, source_ip, dest_ip):
        self.checksum = self.get_checksum(source_ip, dest_ip)
        
        segment = self.encode_header()
        if len(self.data) > 0:
            segment += self.data

        return segment


    # get the checksum for this tcp segment
    def get_checksum(self, source_ip, dest_ip):
        # encode header with placeholder checksum
        self.checksum = 0
        checksumless_header = self.encode_header()

        pseudo_header = self.create_pseudo_header(source_ip, dest_ip, len(checksumless_header))

        # construct segment with pseudo header to get checksum
        assembled_packet = pseudo_header + checksumless_header
        if len(self.data) > 0:
            assembled_packet += self.data

        return utils.calculate_checksum(assembled_packet)


    # encode header with pack
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


    # create pseudo header (static parts of IP header - https://www.baeldung.com/cs/pseudo-header-tcp)
    def create_pseudo_header(self, source_ip, dest_ip, header_len):
        # 8 bits of 0s
        reserved = 0
        # protocol field of IP header
        ip_protocol = socket.IPPROTO_TCP
        # length of TCP segment
        tcp_length = header_len + len(self.data)

        return struct.pack('!4s4sBBH',
            socket.inet_aton(str(source_ip)),
            socket.inet_aton(str(dest_ip)),
            reserved,
            ip_protocol,
            tcp_length
        )


    # validate port and checksum for incoming tcp packets
    def is_valid(self, dst_port, source_ip, dest_ip):
        pseudo_header = self.create_pseudo_header(source_ip, dest_ip, self.data_offset * 4)
        checksum = utils.calculate_checksum(pseudo_header + self.assemble(source_ip, dest_ip))

        return self.destination_port == dst_port and checksum == 0


    # unpack assembled tcp segment 
    @staticmethod
    def disassemble(assembled_segment):
        # unpack assembled tcp segment
        unpacked_header = struct.unpack('!HHLLBBH', assembled_segment[:16])
        [checksum] = struct.unpack('H', assembled_segment[16:18])

        # unpack attributes
        source_port = unpacked_header[0]
        dest_port = unpacked_header[1]
        sequence_number = unpacked_header[2]
        ack_number = unpacked_header[3]
        data_offset = (unpacked_header[4]) >> 4
        flags = unpacked_header[5]
        window = unpacked_header[6]
        # don't need urgent_pointer
        data = assembled_segment[data_offset * 4:]

        fin = flags & 0x01
        ack = (flags & 0x10) >> 4
        syn = (flags & 0x02) >> 1

        # build tcp segment and return
        segment = TCPSegment(source_port, dest_port, sequence_number, ack_number, window, ack, syn, fin, data)
        segment.checksum = checksum
        return segment


# Keep track of in-flight packets
class TCPSegmentWrapper():
    def __init__(self, packet, ack_number):
        self.packet = packet
        self.ack_number = ack_number
        # retransmit packet if it times out
        self.timer = threading.Timer(constants.TIMEOUT_SECONDS, TransportSocket.resend_packet, [self])



# Custom TCP Socket
class TransportSocket:
    def __init__(self):
        # use custom IP socket to send/receive data to/from
        self.ip_socket = IPSocket()

        # keep track of ports
        self.source_port = random.randint(0, constants.MAX_INT16)
        self.destination_port = 0

        # state of connection
        self.connected = False
        self.finned = False
        self.fin_received = False
        self.cwnd = 1

        # keep track of seq/ack numbers
        self.sequence_number = random.randint(0, constants.MAX_INT32)
        self.ack_number = 0

        # keep track of inflight packets (retransmission) and unexpected packets
        self.inflight_packets = []
        self.receive_buffer = []
        

    # connect with host and port
    def connect(self, socket_addr):
        host, self.dest_port = socket_addr
        self.ip_socket.connect(socket.gethostbyname(host))
        self.send_syn()


    # if packet times out, resend it and reset cwnd
    def resend_packet(self, packet_wrapper):
        self.cwnd = 1
        self.inflight_packets.remove(packet_wrapper)
        self.send(packet_wrapper.packet)


    # receive all data until fin observed
    def receive_all(self):
        message = b''
        while not self.fin_received and not self.finned:
            received_data = self.receive_and_parse()
            if received_data:
                message += received_data
        return message


    # receive a single packet, filter invalid, handle flags, return data
    def receive_and_parse(self):
        received = self.ip_socket.receive()
        segment = TCPSegment.disassemble(received)

        # drop packets with wrong port/checksum
        if not segment.is_valid(self.source_port, self.ip_socket.source_ip_address, self.ip_socket.dest_ip_address):
            return

        # force connection if not connected to server yet
        if not self.connected:
            self.force_connect(segment)
            return

        # drop packet if already received or outside of window
        if self.ack_number > segment.sequence_number or \
            segment.sequence_number > self.ack_number + constants.MAX_INT16:
            return

        # unexpected packet (e.g. out of order) will be added to buffer 
        if self.ack_number < segment.sequence_number:
            self.receive_buffer.append(segment)
            self.receive_buffer.sort(key = lambda packet: (self.get_next_sequence_no(packet.sequence_number, -self.ack_number)))

        # check for flags and return data from segment
        self.check_ack(segment)
        self.check_fin(segment)
        if not self.fin_received:
            return self.read_data(segment)


    # if connection not initialized, force a connection
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
        # ack all packets up to latest packet
        if packet.ack == 1:
            num_acked = 0
            for packet_infl in self.inflight_packets:
                if packet_infl.ack_number <= packet.ack_number:
                    self.sequence_number += len(packet_infl.packet.data)
                    num_acked += 1
                else:
                    break

            # update inflight packets state and increase congestion window
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


    # Given non-fin, in-order packet, update state and read tcp segment data
    def read_data(self, segment):
        self.ack_number += len(segment.data)
        data = segment.data

        # handle packets in buffer
        for packet in self.receive_buffer:
            if packet.sequence_number == self.ack_number:
                data += packet.data
                self.ack_number += len(packet.data)
                self.receive_buffer.remove(packet)

                self.check_fin(packet)
                if self.fin_received:
                    return data
            else:
                break

        # send ack, return data for ACKed packets
        self.send_ack()
        return data   


    # send a request with the given packet data
    def send_data(self, data):
        segment = TCPSegment(self.source_port, self.dest_port, self.sequence_number, self.ack_number, self.cwnd, 1, 0, 0, data)
        self.send(segment)


    # send the given tcp segment
    def send(self, segment, append_window = True):
        # get ack number based on seq number
        data_len = 1 if segment.syn == 1 or segment.fin == 1 else len(segment.data)
        ack_number = self.get_next_sequence_no(segment.sequence_number, data_len)

        # manage inflight packets
        inflight_packet = TCPSegmentWrapper(segment, ack_number)
        if append_window:
            self.inflight_packets.append(inflight_packet)

        # send encoded data to network layer
        data = inflight_packet.packet.assemble(
            self.ip_socket.source_ip_address,
            self.ip_socket.dest_ip_address
        )
        self.ip_socket.send_data(data)
        

    # get next sequence number with wrap-around
    def get_next_sequence_no(self, sequence_number, data_len):
        return (sequence_number + data_len) % constants.MAX_INT32

    
    # build basic TCP packet without data (used to send ack/syn/fin)
    def basic_tcpsegment_builder(self, ack, syn, fin):
        return TCPSegment(
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
        syn_packet = self.basic_tcpsegment_builder(0, 1, 0)
        self.send(syn_packet)

        # discard other packets
        while not self.connected:
            self.receive_and_parse()

    
    # send a fin packet
    def send_fin(self):
        fin_packet = self.basic_tcpsegment_builder(1, 0, 1)
        self.send(fin_packet)


    # send an ack packet
    def send_ack(self):
        ack_packet = self.basic_tcpsegment_builder(1, 0, 0)
        self.send(ack_packet, False)

    
    # close connection with fin
    def close(self):
        if not self.finned:
            self.send_fin()
            self.finned = True

        # drain queue, throw away data
        while not self.fin_received:
            self.receive_and_parse()

        # close ip socket
        self.ip_socket.close()
        return