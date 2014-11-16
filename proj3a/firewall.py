#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        # TODO: Load the firewall rules (from rule_filename) here.
        # print 'I am supposed to load rules from %s, but I am feeling lazy.' % \
        #        config['rule']
        self.rules = categorize_rules(config['rule'])
        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        self.geoipdb = load_geoipdb('geoipdb.txt')
        # TODO: Also do some initialization if needed.

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.

        #extract ip_header_length, if shorter than 5, return;
        ip_header_length = ...

        if(ip_header_length < 5)
            return
        checker = PacketChecker(self.rules, self.geoipdb, ip_header_length);
        
        if(checker.check_valid(pkt, pkt_dir)):
            send/recevie

    # TODO: You can add more methods as you want.

    # categorize rules by their protocol name (i.e. tcp, icmp, udp, dns)
    # return dictionary {"tcp", rules; "udp":rules; ...}
    def categorize_rules(self, rules):

# TODO: You may want to add more classes/functions as well.

class PacketChecker:
    # rules: rules loaded from given file, a dictionary: {"tcp", rules; "udp":rules; ...}
    # geoipdb: ip <-> country code loaded from given file
    # ip_length: ip_length
    def __init__(self, rules, geoipdb, ip_header_length):


    # take a decoded packet and direction
    def check_valid(self, packet, packet_dir):


    # decode pakcet
    # return a decoded packet (type, ip, port) 
    def decode_packet(self, packet, packet_dir):

    # decode packet
    # return a decoded dns packet (type, address_name)
    def decode_dns_packet(self, packet):


    # check which the country this ip belongs to
    # return country code
    def ip_belong_to_country(self, ip, geoipdb):



