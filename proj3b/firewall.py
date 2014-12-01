#!/usr/bin/env python


from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import struct
import socket

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
	
        # TODO: Load the firewall rules (from rule_filename) here.
        
        self.rules = self.categorize_rules(config['rule'])

	
        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        self.geoipdb = self.load_geoipdb('geoipdb.txt')
        # TODO: Also do some initialization if needed.
	

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        #extract ip_header_length, if shorter than 5, return;
        ip_header_length = (struct.unpack('!B', pkt[0])[0] & 0xF)* 4

        if ip_header_length < 20:
            return
        checker = PacketChecker(self.rules, self.geoipdb, ip_header_length)
        
	indicator = checker.check_pass(pkt, pkt_dir)
	#proj 3b
        if(indicator == 'deny'):
	    RSTPacket = checker.make_RST(pkt)

	    #dns packet with type AAAA
	    if RSTPacket == None:
		return


	    if RSTPacket[0] == 'tcp':
	   	print "sending rst packet..."
	        if pkt_dir == PKT_DIR_INCOMING:
		    self.iface_ext.send_ip_packet(RSTPacket[1])
	        else:
		    self.iface_int.send_ip_packet(RSTPacket[1])
	    else:
		print "sending dns response..."
		self.iface_int.send_ip_packet(RSTPacket[1])
	    #self.ifact_ext.send_ip_packet(RSTPacket)

	#proj 3b
	elif(indicator == True):
	    if pkt_dir == PKT_DIR_INCOMING:
                self.iface_int.send_ip_packet(pkt)
            elif pkt_dir == PKT_DIR_OUTGOING:
                self.iface_ext.send_ip_packet(pkt)
	else:
	   return
    # TODO: You can add more methods as you want.

    # categorize rules by their protocol name (i.e. tcp, icmp, udp, dns)
    # return dictionary {"tcp", rules; "udp":rules; ...}
    def categorize_rules(self, rules_name):
        rules = {"tcp": [], "icmp": [], "udp": [], "dns": []}
        rules_file = open(rules_name, 'r')
        line = rules_file.readline()
        while line != '':
	    
            if line[0] == '%' or not line.strip():
                line = rules_file.readline()
                continue
            rule = line.lower().split()
            protocol_type = rule[1]

            if(protocol_type != "dns"):
                rules[protocol_type].append([rule[0], rule[2], rule[3]])
            else:
                rules[protocol_type].append([rule[0], rule[2]])
	    line = rules_file.readline()
        return rules



    # return geoipdb list --> [[(start_ip, end_ip), country1], ...]
    def load_geoipdb(self, file_name):
        db = []
        geo_file = open(file_name, 'r')
        line = geo_file.readline()
        while line != '':
            if not line.strip():
                line = geo_file.readline()
                continue
            start_ip, end_ip, country = line[:-1].split(' ')
            db.append([(ip_to_int(start_ip), ip_to_int(end_ip)), country.lower()])
            line = geo_file.readline()
	return db


#change ip address to a int value
def ip_to_int(ip):
    a, b, c, d = ip.split('.')
    return int(a) * (2 ** 24) + int(b) * (2 ** 16) + int(c) * (2 ** 8) + int(d)

#proj 3b
def compute_checksum_ip(pkt, length):
    i = 0
    sum = 0
    while i < length - 1:
	if i == 10:
	    i += 2
	    continue
	sum += struct.unpack('!H', pkt[i: i + 2])[0]
	i += 2
    if length % 2 != 0:
	sum += struct.unpack('!B', pkt[i: i + 1])[0]

    while sum >> 16 != 0:
	sum = (sum & 0xFFFF) + (sum >> 16)
    return ~sum & 0xFFFF
def compute_checksum_tcp(pkt, length, ip_pkt):
    i = 0
    sum = 0
    while i < length - 1:
	if i == 16:
	    i += 2
	    continue
	sum += struct.unpack('!H', pkt[i: i + 2])[0]
	i += 2
    if length % 2 != 0:
	sum += struct.unpack('!B', pkt[i: i + 1])[0]

    sum += struct.unpack('!H', ip_pkt[12: 14])[0]
    sum += struct.unpack('!H', ip_pkt[14: 16])[0]
    sum += struct.unpack('!H', ip_pkt[16: 18])[0]
    sum += struct.unpack('!H', ip_pkt[18: 20])[0]
    sum += 0x06
    sum += 20
    while sum >> 16 != 0:
	sum = (sum & 0xFFFF) + (sum >> 16)
	
    
    return ~sum & 0xFFFF
def compute_checksum_udp(pkt, length, ip_pkt):
    i = 0
    sum = 0
    while i < length - 1:
	if i == 6:
	    i += 2
	    continue
	sum += struct.unpack('!H', pkt[i: i + 2])[0]
	i += 2
    if length % 2 != 0:
	sum += struct.unpack('!B', pkt[i: i + 1])[0]

    sum += struct.unpack('!H', ip_pkt[12: 14])[0]
    sum += struct.unpack('!H', ip_pkt[14: 16])[0]
    sum += struct.unpack('!H', ip_pkt[16: 18])[0]
    sum += struct.unpack('!H', ip_pkt[18: 20])[0]
    sum += 17
    sum += length
    while sum >> 16 != 0:
	sum = (sum & 0xFFFF) + (sum >> 16)
	
    
    return ~sum & 0xFFFF


#proj 3b

# TODO: You may want to add more classes/functions as well.

class PacketChecker:
    # rules: rules loaded from given file, a dictionary: {"tcp", rules; "udp":rules; ...}
    # geoipdb: ip <-> country code loaded from given file
    # ip_length: ip_length
    def __init__(self, rules, geoipdb, ip_header_length):
        self.rules = rules
        self.geoipdb = geoipdb
        self.ip_header_length = ip_header_length

    # take a packet and direction
    def check_pass(self, packet, packet_dir):
	
        decoded_packet = self.decode_packet(packet, packet_dir)
        if decoded_packet == None:
            return False
        protocol_type = decoded_packet[0]
        protocol_rules = self.rules[protocol_type]
	
	

        if_pass = True

        if protocol_type != 'dns':
            ip = decoded_packet[1]
            port = decoded_packet[2]

	    
            for curr_rule in protocol_rules:
		#if curr_rule[0] == 'deny':
		    #return 'deny'
                ip_rule = curr_rule[1]
                port_rule = curr_rule[2]
		
                if ip_rule == 'any' or ip_rule == '0.0.0.0/0':
                    if port_rule == 'any':
			if curr_rule[0] == 'deny':
			    return 'deny'
                        if_pass = True if curr_rule[0] == 'pass' else False
                    # port in rule is a range
                    elif '-' in port_rule:
                        start, end = port_rule.split('-')
                        if port in range(int(start), int(end) + 1):   
			    if curr_rule[0] == 'deny':
				return 'deny'                     
                            if_pass = True if curr_rule[0] == 'pass' else False
		    # port in rule is a number
                    else:
                        if str(port) == port_rule:
			    if curr_rule[0] == 'deny':
				return 'deny'
                            if_pass = True if curr_rule[0] == 'pass' else False
                # ip rule is 2 byte country code
                elif len(ip_rule) == 2:
                    country = self.find_country(ip, self.geoipdb)
                    if(country == ip_rule):
                        if port_rule == 'any':
			    if curr_rule[0] == 'deny':
				return 'deny'
                            if_pass = True if curr_rule[0] == 'pass' else False
                        # port in rule is a range
                        elif '-' in port_rule:
                            start, end = port_rule.split('-')
                            if port in range(int(start), int(end) + 1):    
				if curr_rule[0] == 'deny':
				    return 'deny'                    
                                if_pass = True if curr_rule[0] == 'pass' else False
		        # port in rule is a number
                        else:
                            if str(port) == port_rule:
				if curr_rule[0] == 'deny':
				    return 'deny'
                                if_pass = True if curr_rule[0] == 'pass' else False
                # ip rule is prefix expression
                elif '/' in ip_rule:
                    prefix, prefix_len = ip_rule.split('/')
                    prefix_len = int(prefix_len)
                    if(self.ip_match_prefix(ip, prefix, prefix_len)):
                        if port_rule == 'any':
			    if curr_rule[0] == 'deny':
				return 'deny'
                            if_pass = True if curr_rule[0] == 'pass' else False
                        # port in rule is a range
                        elif '-' in port_rule:
                            start, end = port_rule.split('-')
                            if port in range(int(start), int(end) + 1): 
				if curr_rule[0] == 'deny':
				    return 'deny'                       
                                if_pass = True if curr_rule[0] == 'pass' else False
		        # port in rule is a number
                        else:
                            if str(port) == port_rule:
				if curr_rule[0] == 'deny':
				    return 'deny'
                                if_pass = True if curr_rule[0] == 'pass' else False
                # ip rule is an ip address
                else:		    
                    if(ip == ip_rule):			
                        if port_rule == 'any':
			    if curr_rule[0] == 'deny':
				return 'deny'
                            if_pass = True if curr_rule[0] == 'pass' else False
                        # port in rule is a range
                        elif '-' in port_rule:
                            start, end = port_rule.split('-')
                            if port in range(int(start), int(end) + 1):  
				if curr_rule[0] == 'deny':
				    return 'deny'                      
                                if_pass = True if curr_rule[0] == 'pass' else False
		        # port in rule is a number
                        else:
                            if str(port) == port_rule:
				if curr_rule[0] == 'deny':
				    return 'deny'
                                if_pass = True if curr_rule[0] == 'pass' else False
            return if_pass 
        # dns type rule applied
        else:
            domain = decoded_packet[1]
            for curr_rule in protocol_rules:
                domain_rule  = curr_rule[1]
                if self.domain_match(domain, domain_rule):
		    if curr_rule[0] == 'deny':
			return 'deny'
                    if_pass = True if curr_rule[0] == 'pass' else False

	    return if_pass



    # decode pakcet
    # return a decoded packet (type, ip, port) or ('dns', domain)
    # ip is in form: xxx.xxx.xxx.xxx
    def decode_packet(self, packet, packet_dir):
        protocol_num = struct.unpack('!B', packet[9])[0]
        if packet_dir == PKT_DIR_INCOMING:
            ip_addr = socket.inet_ntoa(packet[12: 16])
        else:
            ip_addr = socket.inet_ntoa(packet[16: 20])

	#proj 3b
	checksum = struct.unpack('!H',packet[10: 12])[0]
	#print "checksum: {}".format(checksum)
	#print compute_checksum_ip(packet, self.ip_header_length)
	#proj 3b

        #packet after ip header
        app_lvl_packet = packet[self.ip_header_length: ]


        if protocol_num == 1:
            protocol_type = 'icmp'
            #icmp type is the first byte after ip header
            icmp_type = int(struct.unpack('!B', app_lvl_packet[0])[0])
            return (protocol_type, ip_addr, icmp_type)
        elif protocol_num == 6:
            protocol_type = 'tcp'
            if packet_dir == PKT_DIR_INCOMING:
                port = struct.unpack('!H', app_lvl_packet[0: 2])[0]
            else:
                port = struct.unpack('!H', app_lvl_packet[2: 4])[0]
            return (protocol_type, ip_addr, port)
        elif protocol_num == 17:
            protocol_type = 'udp'
            if packet_dir == PKT_DIR_INCOMING:
                port = struct.unpack('!H', app_lvl_packet[0: 2])[0]
            else:
                port = struct.unpack('!H', app_lvl_packet[2: 4])[0]

            if packet_dir == PKT_DIR_OUTGOING and port == 53:
                protocol_type = 'dns'
                decoded_dns_packet = self.decode_dns_packet(app_lvl_packet[8: ], ip_addr, port)
                return decoded_dns_packet

            return (protocol_type, ip_addr, port)
        
    # decode a dns packet
    # return a decoded dns packet (type, address_name, qtype)
    def decode_dns_packet(self, dns_packet, ip_addr, port):
	    
	    qdcount = struct.unpack('!H', dns_packet[4: 6])[0]
	    if qdcount != 1:
		print "qdcount {}".format(qdcount)
		return None
	    ancount = struct.unpack('!H', dns_packet[6: 8])[0]
	    nscount = struct.unpack('!H', dns_packet[8: 10])[0]

	    qname_end = 12
	    while dns_packet[qname_end] != chr(0):
		qname_end += 1
	    qname_end += 1


	    qname = ""
	    for i in range(12, qname_end):
		char = dns_packet[i]
		#check if the character is in a correct ascii range
		if ord(char) in range(32, 127):
		    qname += char
		else:
		    qname += ' '
	   
	    #e.g.  ['www', 'google', 'com']
	    qname = qname.split()

	    qtype = struct.unpack('!H', dns_packet[qname_end: qname_end + 2])[0]
	    qclass = struct.unpack('!H', dns_packet[qname_end + 2: qname_end + 4])[0]

	    #print "qtype: {}".format(qname)
	    if (qtype == 1 or qtype == 28) and qclass == 1:
		return ('dns', qname, qtype, qclass, qname_end)
	    
	    return ('udp', ip_addr, port)
    # check which the country this ip belongs to
    # return country code
    def find_country(self, ip, geoipdb):
        s = 0
        e = len(geoipdb) - 1
        ip_int = ip_to_int(ip)

        while s <= e:
            mid = int((s + e) / 2)
            ip_range, country = geoipdb[mid]
            if ip_int in range(ip_range[0], ip_range[1] + 1):
                return country
            if ip_int < ip_range[0]:
                e = mid - 1
            else:
                s = mid + 1
        return None

    #def find_country(self, ip)
    def ip_match_prefix(self, ip, prefix, prefix_len):
        ip_split = ip.split('.')
        prefix_split = prefix.split('.')

        ip_after_prefix = int((32 - prefix_len) / 8)
        ip_after_prefix_remain = int((32 - prefix_len) % 8)

        ip_prefix = ip_split[0: 4 - ip_after_prefix]
        prefix = prefix_split[0: 4 - ip_after_prefix]

        ip_prefix[-1] = int(ip_prefix[-1]) >> ip_after_prefix_remain << ip_after_prefix_remain
        prefix[-1] = int(prefix[-1]) >> ip_after_prefix_remain << ip_after_prefix_remain

        return ip_prefix == prefix

    # domain in form: e.g. [www, google, com]
    # domain_rule in form: e.g. *.google.com
    def domain_match(self, domain, domain_rule):
	
        domain_rule = domain_rule.split('.')
        i = len(domain) - 1
        j = len(domain_rule) - 1
	
	

        while i >= 0 and j >= 0:
            if domain_rule[j] == '*':
                return True
            elif domain[i] != domain_rule[j]:
                return False
            i -= 1
            j -= 1
        if i == -1 and j != -1:
            return False
        elif i != -1 and j == -1:
            return True if domain_rule[0] == '*' else False
        else:
            return True if (domain_rule[0] == '*' or domain_rule[0] == domain[0]) else False

    #proj 3b
    def make_RST(self, pkt):
	print "handling deny"
	ip_header_length = 20
	protocol_num = struct.unpack('!B', pkt[9])[0]
	new_packet = pkt
	
	#exchange dest address and src address
	#new_packet[12: 16] = pkt[16: 20]
	new_packet = new_packet[0: 12] + pkt[16: 20] + new_packet[16: ]
	#new_packet[16: 20] = pkt[12: 16]
	new_packet = new_packet[0: 16] + pkt[12: 16] + new_packet[20: ]
	checksum = compute_checksum_ip(new_packet, self.ip_header_length)
	#new_packet[10: 12] = struct.pack('!H', checksum)
	new_packet = new_packet[0: 10] + struct.pack('!H', checksum) + new_packet[12: ]
	

	#tcp#
	if protocol_num == 6:
	    #tcp lvl packet handling
	    app_lvl_packet = pkt[self.ip_header_length: ]
	    new_app_packet = pkt[self.ip_header_length: ]
	    #exchange dest port and src port
	    #new_app_packet[0: 2] = app_lvl_packet[2: 4]
	    new_app_packet = app_lvl_packet[2: 4] + new_app_packet[2: ]
	    #new_app_packet[2: 4] = app_lvl_packet[0: 2]
	    new_app_packet = new_app_packet[0: 2] + app_lvl_packet[0: 2] + new_app_packet[4: ]
	    #set new flags
	    flags = struct.unpack('!B', app_lvl_packet[13])[0]
	    new_flags = flags & 0x00
	    new_flags = new_flags | 0x04
	    new_flags = new_flags | 0x10
	    #new_app_packet[12] = struct.pack('!B', new_flags)
	    new_app_packet = new_app_packet[0: 13] + struct.pack('!B', new_flags) + new_app_packet[14: ]

	    #update tcp header ack
	    seq = struct.unpack('!L', app_lvl_packet[4: 8])[0]
	    new_app_packet = new_app_packet[0: 8] + struct.pack('!L', seq + 1) + new_app_packet[12: ]
	    #update tcp header length and checksum
	    new_app_packet = new_app_packet[0: 12] + struct.pack('!B', 5 << 4) + new_app_packet[13: ]
	    #offset = struct.unpack('!B', app_lvl_packet[12])[0] >> 4
	    new_checksum = compute_checksum_tcp(new_app_packet,  20, new_packet)
	
	    #new_app_packet[16: 18] = struct.pack('!H', new_checksum)
	    new_app_packet = new_app_packet[0: 16] + struct.pack('!H', new_checksum) + new_app_packet[18: ]
	    #print "checksum: {}, correct checksum: {}".format(new_checksum, compute_checksum_tcp(new_app_packet, 20, new_packet))
	    #new_packet[self.ip_header_length: ] = new_app_packet
	    new_packet = new_packet[0: self.ip_header_length] + new_app_packet[0: 20]
		

	    #update ip header's total length and checksum
	    new_packet = new_packet[0: 2] + struct.pack('!H', self.ip_header_length + 20) + new_packet[4: ]
	    #print "new packet length: {}".format(struct.unpack('!B', new_app_packet[12])[0] >> 4)
	    checksum = compute_checksum_ip(new_packet, self.ip_header_length)
	    #new_packet[10: 12] = struct.pack('!H', checksum)
	    new_packet = new_packet[0: 10] + struct.pack('!H', checksum) + new_packet[12: ]
	
	    return ('tcp', new_packet)
	
	#dns#
	else:
	    app_lvl_packet = pkt[self.ip_header_length: ]
	    new_app_packet = pkt[self.ip_header_length: ]
	    dns_packet = new_app_packet[8: ]
	    new_dns_packet = new_app_packet[8: ]

	    #new_app_packet[0: 2] = app_lvl_packet[2: 4]
	    new_app_packet = app_lvl_packet[2: 4] + new_app_packet[2: ]
	    #new_app_packet[2: 4] = app_lvl_packet[0: 2]
	    new_app_packet = new_app_packet[0: 2] + app_lvl_packet[0: 2] + new_app_packet[4: ]
	    
	    #['dns', 'qname', 'qtype', 'qclass', 'qname_end_pos']
	    decoded_packet = self.decode_dns_packet(dns_packet, 0, 0) 
	    if decoded_packet == None:
		print "decode packet is None"
		return None
	    protocol, qname, qtype, qclass, qname_end_pos = decoded_packet
	    if qtype == 28:
		print "type is AAAA"
		return None
	    #set qr to 1 denote as response
	    new_qr = struct.unpack('!B', dns_packet[2: 3])[0] | 0x80
	    new_dns_packet = new_dns_packet[0: 2] + struct.pack('!B', new_qr) + new_dns_packet[3: ]

	    #set rcode to 0
	    new_rcode = struct.unpack('!B', dns_packet[3: 4])[0] & 0xF0
	    new_dns_packet = new_dns_packet[0: 3] + struct.pack('!B', new_rcode) + new_dns_packet[4: ]
	    #set ANCOUNT to 1
	    new_dns_packet = new_dns_packet[0: 6] + struct.pack('!H', 1) + new_dns_packet[8: ]
	    #set NSCOUNT to 0
	    new_dns_packet = new_dns_packet[0: 8] + struct.pack('!H', 0) + new_dns_packet[10: ]
	    #set ARCOUNT to 0
	    new_dns_packet = new_dns_packet[0: 10] + struct.pack('!H', 0) + new_dns_packet[12: ]
	    #question part in response packet be kept same
	    answer_start = qname_end_pos + 4
	    answer_name_end = answer_start + qname_end_pos - 12
	    #set RNAME section
	    new_dns_packet = new_dns_packet[0: answer_start] + new_dns_packet[12: qname_end_pos] + new_dns_packet[answer_name_end: ]
	    #set RTYPE section
	    new_dns_packet = new_dns_packet[0: answer_name_end] + struct.pack('!H', 1) + new_dns_packet[answer_name_end + 2: ]
	    #set RCLASS section
	    new_dns_packet = new_dns_packet[0: answer_name_end + 2] + struct.pack('!H', 1) + new_dns_packet[answer_name_end + 4: ]
	    #set TTL section
	    new_dns_packet = new_dns_packet[0: answer_name_end + 4] + struct.pack('!L', 1) + new_dns_packet[answer_name_end + 8: ]
	    kitten_ip = "54.173.224.150"
	    kitten_hex = socket.inet_aton(kitten_ip)
	    answer_end = answer_name_end + 8 + 2 + len(kitten_hex)
	    #set RDLENGTH
	    new_dns_packet = new_dns_packet[0: answer_name_end + 8] + struct.pack('!H', len(kitten_hex)) + new_dns_packet[answer_name_end + 10: ]
	    #set RDATA
	    new_dns_packet = new_dns_packet[0: answer_name_end + 10] + kitten_hex
	
	    new_app_packet = new_app_packet[0: 8] + new_dns_packet

	    #update udp_header total length and checksum
	    new_udp_header_length = 8 + answer_end
	    print "length: {} should be: {}".format(new_udp_header_length, len(new_app_packet))
	    new_app_packet = new_app_packet[0: 4] + struct.pack('!H', new_udp_header_length) + new_app_packet[6: ]
	    new_udp_checksum = compute_checksum_udp(new_app_packet, new_udp_header_length, new_packet)
	    new_app_packet = new_app_packet[0: 6] + struct.pack('!H', new_udp_checksum) + new_app_packet[8: ]

	    #update ip_header total length and checksum
	    new_packet = new_packet[0: self.ip_header_length] + new_app_packet
	    new_packet = new_packet[0: 2] + struct.pack('!H', self.ip_header_length + new_udp_header_length) + new_packet[4: ]
	    #print "new packet length: {}".format(struct.unpack('!B', new_app_packet[12])[0] >> 4)
	    checksum = compute_checksum_ip(new_packet, self.ip_header_length)
	    #new_packet[10: 12] = struct.pack('!H', checksum)
	    new_packet = new_packet[0: 10] + struct.pack('!H', checksum) + new_packet[12: ]
	
	    #print new_packet[-12: ]
	    return ('dns', new_packet)

	
    #proj 3b










