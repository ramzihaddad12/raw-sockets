CR = '\r'
CRLF = '\r\n'
END = '\r\n\r\n'

TIMEOUT_SECONDS = 60
MAX_PACKET_SIZE = 1024
MAX_INT32 = pow(2, 32) - 1 # 4,294,967,295
MAX_INT16 = pow(2, 16) - 1 # 65,535
MAX_CWND = 1000

ETH_P_ALL = 0x0003 # For all packets
ETH_P_IP = 0x0800 # For IP Packets
ETH_P_ARP = 0x0806 # For ARP Packets
MIN_ETHERNET_SIZE = 46