#!/usr/bin/env python3

import socket
import struct
import textwrap
import argparse
import csv



fields = ['mac_src','mac_dest','frame_protocol','frame_data',
			'ip_ttl','ip_protocol','ip_src','ip_dest','ip_version','ip_headerlength','ip_data',
			'icmp_type','icmp_code','icmp_checksum','icmp_data',
			'tcp_src_port','tcp_dest_port','tcp_sequence','tcp_acknowledgement',
			'flag_urg','flag_ack','flag_psh','flag_rst','flag_syn','flag_fin','tcp_data',
			'udp_src_port','udp_dest_port','udp_size','udp_data']

#Get local ip
def get_local_ip():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	try:
		s.connect(('10.255.255.255',1))
		IP = s.getsockname()[0]
	except Exception:
		IP = '127.0.0.1'
	finally:
		s.close()
	return IP


#Wrapper class for display operations
class TrafficDisplay:
	TAB_1 = '\t - '
	TAB_2 = '\t\t - '
	TAB_3= '\t\t\t - '
	TAB_4 = '\t\t\t\t - '

	DATA_TAB_1= '\t '
	DATA_TAB_2= '\t\t '
	DATA_TAB_3= '\t\t\t '
	DATA_TAB_4= '\t\t\t\t '

	#Display multi-line data
	@staticmethod
	def format_multi_line(prefix, string, size=80):
		size -= len(prefix)
		if isinstance(string, bytes):
			string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
			if size %2:
				size -=1
		return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
	


	#Method for printing ethernet frame
	@staticmethod
	def print_ethernet(frame):
		print('\nEthernet Frame:')
		print(TrafficDisplay.TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(frame.getDestMACFormatted(),frame.getSrcMACFormatted(),frame.protocol))


	#Method for printing ipv4 packet
	@staticmethod
	def print_ipv4(packet):
			print(TrafficDisplay.TAB_1 + 'IPv4 Packet: ')
			print(TrafficDisplay.TAB_2 + 'Version: {}, Header Lenght: {}, TTL: {}'.format(packet.version, packet.header_length, packet.ttl))
			print(TrafficDisplay.TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(packet.protocol, packet.getIPSrcFormat(), packet.getIPDestFormat()))

	#Methods for printing various Transport layer protocols
	@staticmethod
	def print_icmp(ipv4_packet):
		icmp_type, code, checksum, data = TransportData.icmp_packet(ipv4_packet.data)
		print(TrafficDisplay.TAB_1 + 'ICMP Packet: ')
		print(TrafficDisplay.TAB_2 + 'Type: {}, Code {}, Checksum{},'.format(icmp_type, code, checksum))
		print(TrafficDisplay.TAB_2 + 'Data: ')
		print(TrafficDisplay.format_multi_line(TrafficDisplay.DATA_TAB_3, data))

	def print_tcp(ipv4_packet):
		(src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = TransportData.tcp_segment(ipv4_packet.data)
		print(TrafficDisplay.TAB_1 + 'TCP Segment:')
		print(TrafficDisplay.TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
		print(TrafficDisplay.TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
		print(TrafficDisplay.TAB_2 + 'Flags:')
		print(TrafficDisplay.TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN:{}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
		print(TrafficDisplay.TAB_2 + 'Data:')
		print(TrafficDisplay.format_multi_line(TrafficDisplay.DATA_TAB_3, data))

	def print_udp(ipv4_packet):
		src_port, dest_port, length, data = TransportData.udp_segment(ipv4_packet.data)
		print(TrafficDisplay.TAB_1 + 'UDP Segment:')
		print(TrafficDisplay.TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))
	

		

#Wrapper class for all layer4 operations
class TransportData:
	# Unpack ICMP packet
	@staticmethod
	def icmp_packet(data):
		icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
		return icmp_type, code, checksum, data[4:]


	# Unpack TCP segment
	@staticmethod
	def tcp_segment(data):
		(src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
		offset = (offset_reserved_flags >> 12)*4
		flag_urg = (offset_reserved_flags &32) >>5
		flag_ack = (offset_reserved_flags &16) >>4
		flag_psh = (offset_reserved_flags &8) >>3
		flag_rst = (offset_reserved_flags &4) >>2
		flag_syn = (offset_reserved_flags &2) >>1
		flag_fin = (offset_reserved_flags &1)
		return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh,flag_rst, flag_syn, flag_fin, data[offset:]

	#Unpack UDP segment
	@staticmethod
	def udp_segment(data):
		src_port, dest_port, size =struct.unpack('! H H 2x H', data[:8])
		return src_port, dest_port, size, data[8:]







#Class that holds an IPv4 packet
class IPv4Packet:
	
	#Constructor that takes in ip data from Ethernet frame:
	def __init__(self, data):
		version_header_length = data[0]
		self.ttl, self.protocol, self.destination, self.source = struct.unpack('! 8x B B 2x 4s 4s', data[:20]) #INVERTED ADDRESSES?!
		
		self.version = version_header_length >>4
		self.header_length = (version_header_length & 15) *4
		self.data = data[self.header_length:]

	#Return formatted ip addresses
	def getIPSrcFormat(self):
		return '.'.join(map(str,self.source))

	def getIPDestFormat(self):
		return '.'.join(map(str,self.destination))






#Class that holds an ethernet frame
class EthernetFrame:
	#Define Constructor, unpacks ehternet frame
	def __init__(self, data):
		self.src_mac, self.dest_mac, proto = struct.unpack('! 6s 6s H', data[:14])    #INVERTED ADDRESSES?!
		self.protocol = socket.htons(proto)
		self.raw_data = data[14:]
		if self.protocol ==8:
			self.ip_data = IPv4Packet(self.raw_data)
		else:
			self.ip_data = None


	#Return string with formatted MAC address for source and destination
	def getSrcMACFormatted(self):
		bytes_str = map('{:02x}'.format, self.src_mac)
		return ':'.join(bytes_str).upper()

				
	def getDestMACFormatted(self):
		bytes_str = map('{:02x}'.format, self.dest_mac)
		return ':'.join(bytes_str).upper()





	

	
#Print to commandline
def printCMD(eth_frame):
	TrafficDisplay.print_ethernet(eth_frame)
	#8 for IPv4
	if eth_frame.protocol == 8:
		ip_packet= eth_frame.ip_data
		TrafficDisplay.print_ipv4(ip_packet)

		#ICMP
		if ip_packet.protocol == 1:
			TrafficDisplay.print_icmp(ip_packet)

		# TCP
		elif ip_packet.protocol == 6:
			TrafficDisplay.print_tcp(ip_packet)

		# UDP
		elif ip_packet.protocol == 17:
			TrafficDisplay.print_udp(ip_packet)

		# Other
		else:
			print(TrafficDisplay.TAB_1 + 'Data:')
			print(TrafficDisplay.TAB_2 + TrafficDisplay.format_multi_line(TrafficDisplay.DATA_TAB_2, ip_packet.data))

	else:
		print('Data:')
		print(TrafficDisplay.format_multi_line(TrafficDisplay.DATA_TAB_1, eth_frame.raw_data))


#Create a row to be written in a csv file from a frame object
def csvRow(frame):


	row = [frame.getSrcMACFormatted(),frame.getDestMACFormatted(),
		frame.protocol,frame.raw_data]
	if frame.protocol==8:
		packet = frame.ip_data
		row.append(packet.ttl)
		row.append(packet.protocol)
		row.append(packet.getIPSrcFormat())
		row.append(packet.getIPDestFormat())
		row.append(packet.version)
		row.append(packet.header_length)
		row.append(packet.data)

		#ICMP
		if packet.protocol == 1:
			icmp_type, icmp_code, icmp_checksum, icmp_data= \
				TransportData.icmp_packet(packet.data)
			row.append(icmp_type)
			row.append(icmp_code)
			row.append(icmp_checksum)
			row.append(icmp_data)

		# TCP
		elif packet.protocol == 6:
			(tcp_src_port, tcp_dest_port, tcp_sequence, tcp_acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, tcp_data) = TransportData.tcp_segment(packet.data)
			row.append('')
			row.append('')
			row.append('')
			row.append('')
			row.append(tcp_src_port)
			row.append(tcp_dest_port)
			row.append(tcp_sequence)
			row.append(tcp_acknowledgement)
			row.append(flag_urg)
			row.append(flag_ack)
			row.append(flag_psh)
			row.append(flag_rst)
			row.append(flag_syn)
			row.append(flag_fin)
			row.append(tcp_data)
		# UDP
		elif packet.protocol == 17:
			udp_src_port, udp_dest_port, udp_length, udp_data = TransportData.udp_segment(packet.data)
			row.append('')
			row.append('')
			row.append('')
			row.append('')
			row.append('')
			row.append('')
			row.append('')
			row.append('')
			row.append('')
			row.append('')
			row.append('')
			row.append('')
			row.append('')
			row.append('')
			row.append('')
			row.append(udp_src_port)
			row.append(udp_dest_port)
			row.append(udp_length)
			row.append(udp_data)
			
	else:
		row.append('')
		row.append('')
		row.append('')
		row.append('')
		row.append('')
		row.append('')
		row.append('')
		row.append('')
		row.append('')
		row.append('')
		row.append('')
		row.append('')
		row.append('')
		row.append('')
		row.append('')
		row.append('')
		row.append('')
		row.append('')
		row.append('')
		row.append('')
		row.append('')
		row.append('')
		row.append('')
		row.append('')
		row.append('')
		row.append('')
	return row



#This can be made more efficient , remove one of the fors
def checkIPinrange(checked_ip,target_ip,wildcard):
	wildcard_string_bytes=wildcard.split(".")
	target_ip_string_bytes=target_ip.split(".")
	checked_ip_string_bytes=checked_ip.split(".")
	
	wildcard_bytes =[]
	target_ip_bytes = []
	checked_ip_bytes =[]
	for i in range(4):
		wildcard_bytes.append(255-int(wildcard_string_bytes[i]))
		target_ip_bytes.append(int(target_ip_string_bytes[i]))
		checked_ip_bytes.append(int(checked_ip_string_bytes[i]))
	for i in range(4):
		if wildcard_bytes[i]&target_ip_bytes[i]!=wildcard_bytes[i]&checked_ip_bytes[i]:
			return False
	return True


#This can be more efficient by only checking set arguments rather than checking for all arguments each time

def checkIPinlist(checked_ip, ip_list):
	for ip in ip_list:
		if checked_ip == ip:
			return True
	return False

def checkIPRestriction(args, packet, local_ip):
	
	match_source=False
	checked_source=False
	



	
	ipsrc = packet.getIPSrcFormat()
	ipdest = packet.getIPDestFormat()

	if args.self!=True and ipsrc==local_ip: return False

	if args.excludesourceip!=None:
		for entry in args.excludesourceip:
			if(ipsrc==entry): return False



	if args.targetsource!=None:
		checked_source=True
		match_source = checkIPinlist(ipsrc, args.targetsource)
		

	
	
	if args.Targetsourcerange!=None and not(checked_source==True and match_source==True):
		checked_source=True
		for entry in args.Targetsourcerange:
			rng,wild= entry.split(" ")
			if checkIPinrange(ipsrc,rng,wild): 
				match_source = True
				break
	
	
	if(checked_source==True and match_source==False):
		return False

	checked_destination=False
	match_destination=False


	if args.targetdestination!=None:
		checked_destination=True
		for entry in args.targetdestination:
			if ipdest ==entry:
				matched_destination=True

	if args.Targetdestinationrange!=None and not (checked_destination and match_destination):
		checked_destination=True
		for entry in args.Targetdestinationrange:
			rng,wild= entry.split(" ")
			if checkIPinrange(ipsrc,rng,wild):
				match_destination=True

	if(checked_destination==True and match_destination==False):
		return False

	if args.Excludesourceiprange!=None:
		for entry in args.Excludesourceiprange:
			rng,wild= entry.split(" ")
			if checkIPinrange(ipsrc,rng,wild): return False

	if args.excludedestip!=None:
		for entry in args.excludedestip:
			if(ipdest==entry): return False

	if args.Excludedestiprange!=None:
		for entry in args.Excludedestiprange:
			rng,wild= entry.split(" ")
			if checkIPinrange(ipdest,rng,wild): return False

	match_protocol=True

	if args.targetprotocol!=None:
		match_protocol=False
		for entry in args.targetprotocol:
			if packet.protocol==int(entry):
				match_protocol=True
				break
	


	return match_protocol


def checkFrameRestriction(args,frame):
	result=True;
	if args.targetmacdestination!=None:
		result=False;
		temp_mac = frame.getDestMACFormatted()
		for entry in args.targetmacdestination:
			if temp_mac == entry:
				result=True
				break
		if not result:
			return False
	if args.targetmacsource!=None:
		result=False;
		temp_mac = frame.getSrcMACFormatted()
		for entry in args.targetmacsource:
			if temp_mac == entry:
				result=True
				break
	return result



def checkSegmentRestricion(args, packet):
	if packet.protocol==6 and (args.targettcpsourceport!=None or args.targettcpdestport!=None):
		src_port, dest_port = TransportData.tcp_segment(packet.data)
		if args.targettcpsourceport!=None and args.targettcpsourceport != src_port: return False
		elif args.targettcpdestport !=None and args.targettcpdestport != dest_port: return False
		else: return True
	elif packet.protocol == 17 and (args.targetudosourceport!=None or args.targetudpdestport!=None):
		src_port, dest_port = TransportData.udp_segment(packet.data)
		if args.targetudpsourceport!=None and args.targetudpsourceport!=src_port: return False
		if args.targetudpdestport!=None and args.targetudpdestport!=dest_port: return False
		else: return True
	else: return True


#Listen for any data on the network
#Better way of doing argument checks using flags
def main():
	conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
	parser = argparse.ArgumentParser()

	#SOMEWHAT TESTED?
	parser.add_argument('-p','--print',help='Prints output to terminal', action='store_true')
	parser.add_argument('-f','--file',default='out.csv',help='Prints output to file')
	
	parser.add_argument('-esip','--excludesourceip',type=str, help='Exclude a source ip address. APPENDABLE', action='append')

	parser.add_argument('-Esip','--Excludesourceiprange', type=str, help='Exclude source ip range using wildcard. APPENDABLE', action='append')

	parser.add_argument('-edip','--excludedestip',type=str, help='Exclude destination ip. APPENDABLE',action='append')

	parser.add_argument('-Edip','--Excludedestiprange',type=str,help='Exclude destination ip range using wildcard. APPENDABLE', action='append')

	parser.add_argument('-s','--self', default=False, action='store_true', help='Include messages coming from self')

	parser.add_argument('-ts','--targetsource',type=str,action='append',help='Only include packets from a source ip. APPENDABLE')

	parser.add_argument('-Ts','--Targetsourcerange',type=str,action='append',help='Only include packets from a certain source range specified using wildcard bits. APPENDABLE')

	parser.add_argument('-td','--targetdestination',type=str,action='append',help='Only target packets with a specific destination. APPENDABLE')

	parser.add_argument('-Td','--Targetdestinationrange',type=str,action='append',help='Only target packets with a destination within a range specified using wildcard bits. APPENDABLE')


	parser.add_argument('-tp','--targetprotocol', type=str,action='append',help='Only process packets that carry a specific protocol. Use protocol code as argument. APPENDABLE')

	
	#UNTESTED
	parser.add_argument('-tsm','--targetmacsource', type=str,action='append',help='Only process frames from a certian mac address (AA:BB:CC:DD...). APPENDABLE')

	parser.add_argument('-tdm','--targetmacdestination', type=str,action='append', help='Only process frames with a certain destination. APPENDABLE')



	#UNTESTED
	parser.add_argument('-ttsp','--targettcpsourceport',type=str,action='append',help='Only process packets that come from a specific tcp source port. Implied tcp target. APPENDABLE')

	parser.add_argument('-ttdp','--targettcpdestport',type=str,action='append',help='Only process packets that have a specific tcp destination port. Implied tcp target. APPENDABLE')
	
	parser.add_argument('-tusp','--targetudpsourceport',type=str,action='append',help='Only process packets that come from a specific udp source port. Implied udp target. APPENDABLE')

	parser.add_argument('-tudp','--targetudpdestport',type=str,action='append',help='Only process packets that have a specific udp destination port. APPENDABLE')

	

	args = parser.parse_args()

	#hostname = socket.gethostname()
	#local_ip = socket.gethostbyname(hostname)
	

	local_ip = get_local_ip()
	print("LOCAL: ",local_ip)

	with open(args.file, 'w') as csvfile:
		writer = csv.writer(csvfile)
		writer.writerow(fields)
		include_self=args.self
		while True:

				
			
			raw_data, addr = conn.recvfrom(65536)
			eth_frame = EthernetFrame(raw_data)

			#apply frame restrictions
			checkFrameRestriction(args,eth_frame)
			if eth_frame.protocol==8:
				#apply ip packet restriction
				if checkIPRestriction(args,eth_frame.ip_data,local_ip)and checkSegmentRestricion(args, eth_frame.ip_data):
					writer.writerow(csvRow(eth_frame))
					if(args.print==True):
						printCMD(eth_frame)
			else:
				#apply other restricions
				writer.writerow(csvRow(eth_frame))
				if(args.print==True):
					printCMD(eth_frame)
			
		
	





if __name__ == '__main__':
	main()
