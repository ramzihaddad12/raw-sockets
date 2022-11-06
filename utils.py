def calculate_checksum(header):
        checksum = 0
        # if there are even number of terms to add 
        if (len(header) % 2 == 0):
            for i in range(0, len(header), 2):
                checksum += header[i] + (header[i + 1] << 8)
            carry = (checksum & 0xffff) + (checksum >> 16)
            checksum = (~carry) & 0xffff
        # if there are off number of terms to add
        else:
            for i in range(0, len(header) - 1, 2):
                checksum += header[i] + (header[i + 1] << 8)
            checksum += header[len(header) - 1]
            carry = (checksum & 0xffff) + (checksum >> 16)
            checksum = (~carry) & 0xffff

        return checksum