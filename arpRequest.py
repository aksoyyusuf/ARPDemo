import struct
import socket
import binascii
import ipaddress
import uuid

sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
sock.bind(("enp0s3", 0))

source_mac = "08:00:27:27:B7:F2"        # sender mac address
source_ip  = "10.0.2.15"                # sender ip address
dest_mac = "\xff\xff\xff\xff\xff\xff"   # target mac address(broadcast)

dest_ip = raw_input("Please enter target IP: ")     # target ip address

# Ethernet Header
protocol = 0x0806                       # 0x0806 for ARP
eth_hdr = struct.pack("!6s6sH", dest_mac, source_mac, protocol)

# ARP header
htype = 1                               # Hardware_type ethernet
ptype = 0x0800                          # Protocol type TCP
hlen = 6                                # Hardware address Len
plen = 4                                # Protocol addr. len
operation = 1                           # 1=request/2=reply
src_ip = socket.inet_aton(source_ip)
dst_ip = socket.inet_aton(dest_ip)
arp_hdr = struct.pack("!HHBBH6s4s6s4s", htype, ptype, hlen, plen, operation, source_mac, src_ip, dest_mac, dst_ip)

packet = eth_hdr + arp_hdr
sock.send(packet)


while True:

	print"Check1"
	packet = sock.recv(2048)    
	print"Check2"
	ethernet_header = packet[0:14]
	ethernet_detailed = struct.unpack("!6s6s2s", ethernet_header)
	arp_header = packet[14:42]
	arp_detailed = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)



	received_ip = str(ipaddress.ip_address(arp_detailed[8]))
	received_mac = binascii.hexlify(ethernet_detailed[1])
	    

	print "Coming IP: ", received_ip
	print "Coming MAC adress: ", received_mac

	print "****************_ETHERNET_FRAME_****************"
	print "Dest MAC:        ", binascii.hexlify(ethernet_detailed[0])
	print "Source MAC:      ", binascii.hexlify(ethernet_detailed[1])
	print "Type:            ", binascii.hexlify(ethernet_detailed[2])
	print "************************************************"
	print "******************_ARP_HEADER_******************"
	print "Hardware type:   ", binascii.hexlify(arp_detailed[0])
	print "Protocol type:   ", binascii.hexlify(arp_detailed[1])
	print "Hardware size:   ", binascii.hexlify(arp_detailed[2])
	print "Protocol size:   ", binascii.hexlify(arp_detailed[3])
	print "Opcode:          ", binascii.hexlify(arp_detailed[4])
	print "Source MAC:      ", binascii.hexlify(arp_detailed[5])
	print "Source IP:       ", socket.inet_ntoa(arp_detailed[6])
	print "Dest MAC:        ", binascii.hexlify(arp_detailed[7])
	print "Dest IP:         ", socket.inet_ntoa(arp_detailed[8])
	print "*************************************************\n"
