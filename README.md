# cs5700-project3-python3

## High Level Approach
Our high level approach was to split the work between the individual layers (application, transport, network, and data link). 

- Our application layer creates a custom socket (TransportSocket), send a GET request to the given URL, and then receive the response and save it to a file with the appropriate name.
- Our transport layer connects to the server (3-way handshake), adds headers to the request, and sends the request from the application layer to the network layer. When receiving a packet, our transport layer handles unexpected packets: out-of-order, already received, outside-of-window, those not destined to us based on port numbers. For expected packets, we ACK and manage our congestion window accordingly. 
- Our network layer builds and adds IP headers onto the TCP segment, and sends it off to our data link layer (ethernet). When receiving a packet, we validate the checksum and filter out packets with based on IP address. 
- Our data link layer connects the source IP address to the destination/site needed via ethernet. When sending a request, we add ethernet headers to the IP datagram, and sends the request to the server. When receiving a packet, we validate MAC addresses and ethernet type. We also use this layer to connect initially to the server and find out its MAC address by broadcasting a message via ethernet.

## TCP/IP Features Implemented
#### TCP Features
- Validating checksum/ports when receiving packets
- Creating checksum/port when sending packets
- 3-way handshake
- Timeout and retransmitting functionality
- Handling out-of-order packets
- Drop duplicate packets
- Manage cwnd
 
#### IP Features
- Validating checksums when receiving packets
- Creating IP datagram with version, header length, total length, protocol ID, and checksum

## Ethernet Features Implemented
- Initially, we need to get the source MAC address and the interface for the local machine
- Then, we are need of sending a broadcast ethernet message (via the broadcast MAC address) to find the destination MAC address
- Finally, we implemented functionality to allow for sending and receiving ARP packets via ethernet by adding and removing the ethernet header 
 
## Challenges Faced
- Handling bytes and hex formats
- Validating and building checksums
- Correctly shifting and `operator&` bits to get the data we wanted when unpacking
- Learning how the IP pseudoheader works to calculate the checksum
- Learning about how ARP packets are structured and how to pack and unpack them (source used: https://en.wikipedia.org/wiki/Address_Resolution_Protocol)
- Sending and receiving packets successfully through ethernet
- Extracting MAC addresses and the machine interface

## Work Distribution
We decided early on that we wanted to tackle the extra credit, so we distributed the work based on layers. Ramzi primarily worked on the lower layers (data link and network), while John primarily worked on the higher layers (transport and application). We knew the assignment was lengthy so we wanted to work in parallel as much as possible, so we discussed high-level functionality that we'd expect from the network and transport layers so we could work concurrently while limiting how much we blocked each other. After putting our parts together, we used Wireshark to debug our code and make the appropriate changes to the corresponding layers.
