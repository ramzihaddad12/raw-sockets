# calculate the checksum for a packet
def calculate_checksum(packet):
        checksum = 0

        for i in range(0, len(packet)-1, 2):
            checksum += packet[i] + ((packet[i+1]) << 8)
        
        # for odd length headers
        if len(packet) % 2 == 1:
            checksum += packet[i]

        while (checksum >> 16):
            checksum = (checksum & 0xffff) + (checksum >> 16)

        return (~checksum) & 0xFFFF