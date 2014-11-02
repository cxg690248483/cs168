import sys
import getopt

import Checksum
import BasicSender


'''
This is a skeleton sender class. Create a fantastic transport protocol here.
'''
class Sender(BasicSender.BasicSender):
    def __init__(self, dest, port, filename, debug=False, sackMode=False):
        super(Sender, self).__init__(dest, port, filename, debug)
        #if sackMode:
            #raise NotImplementedError #remove this line when you implement SACK

        self.file_read = True
        if self.infile == sys.stdin:
                self.file_read = False
        self.data_size = 120
        self.timeout = 0.5
        self.window_size = 5
        self.seqno = -1
        self.window = []
        self.end_seqno = None
        self.msg_type = None
        self.packet_cached = []
        self.sack_list = []
        self.sack_list_copy = []
        self.sack_retrans = False

    def handle_response(self,response_packet):
        if Checksum.validate_checksum(response_packet):
            received_packet_split = self.split_packet(response_packet)
            return received_packet_split
        else:
            print "recv: %s <--- CHECKSUM FAILED" % response_packet
    # Main sending loop.
    def start(self):
        for i in range(5):
            msg = ""
            self.seqno += 1
            if self.file_read:
                msg = self.infile.read(self.data_size)
            else:
                msg = raw_input("Message:")
            self.msg_type = 'data'
            if self.seqno == 0:
                self.msg_type = 'start'
            if msg == "":
                self.msg_type = 'end'
            if msg == "done":
                self.msg_type = 'end'

            packet = self.make_packet(self.msg_type, self.seqno, msg)
            self.send(packet)
            self.packet_cached.append(packet)
            self.window.append(i)
            if self.msg_type == 'end':
                if self.end_seqno is None:
                    self.end_seqno = self.seqno
                    break

        # record the number of duplicate acks #
        dup_ack_num = 0
        
        while True:
            response = self.receive(self.timeout)
            if response is None :
                if self.sack_list == [] and self.sack_retrans is False:
                    self.handle_timeout()
                    # reset dup_ack counter after handle a timeout #
                    dup_ack_num = 0
                    continue
                else:
                    if self.sack_retrans is False:
                        self.sack_list_copy = self.sack_list[:]
                        self.handle_sack_timeout()
                        self.sack_list = []
                        dup_ack_num = 0
                    else:
                        self.handle_sack_timeout()
                    continue

            received_packet = self.handle_response(response)
            
            # if received packet is invalid, ignore it #
            if(received_packet == None):
                continue
            
            if received_packet[0] == "ack":
                ack = int(received_packet[1])
                # check if it is the last seqno received #
                if self.end_seqno is not None and ack == self.end_seqno + 1:
                    break
                if ack < self.window[0]:
                    # if received ack smaller than first elem in window, igore it #
                    continue
                if ack == self.window[0]:
                    dup_ack_num += 1
                    if dup_ack_num == 3:
                        self.handle_dup_ack(ack)
                        # reset dup_ack counter after handle a dup ack #
                        dup_ack_num = 0
                    continue
                else:
                    self.handle_new_ack(ack)
                    # reset dup_ack counter after handle a new ack #
                    dup_ack_num = 0
            
            # below is sack mode #
            else:
                if received_packet[1] is not None :
                    cum_ack,rest=self.split_str(received_packet[1])
                    cum_ack=int(cum_ack)
                    if self.end_seqno is not None and cum_ack == self.end_seqno + 1:
                        break
                    elif rest==[""] :
                        if cum_ack < self.window[0]:
                            continue
                        elif cum_ack == self.window[0]:
                            continue
                        else:
                            self.handle_new_ack(cum_ack)
                            dup_ack_num = 0
                            continue
                    else:
                        if cum_ack != self.window[0]:
                            self.handle_new_ack(cum_ack)
                            dup_ack_num = 0
                        else:
                            dup_ack_num += 1

                        if self.sack_list == []:
                            self.sack_list = self.window[:]

                        for i in rest:
                            i = int(i)
                            try:
                                if self.sack_retrans is False:
                                    self.sack_list.remove(i)
                                else:
                                    self.sack_list_copy.remove(i)

                            except ValueError:
                                pass
                        if dup_ack_num == 3:
                            self.sack_list_copy = self.sack_list[:]
                            self.handle_sack_timeout()
                            self.sack_list = []
                            dup_ack_num = 0
                            continue
                        else:
                            continue


    def handle_sack_timeout(self):
       self.sack_retrans = True
       offset = self.sack_list_copy[0]
       for packet_num in self.sack_list_copy:
           index = packet_num - offset
           packet = self.packet_cached[index]
           self.send(packet)


    def split_str(self,msg):
        pieces = msg.split(';')
        cum_ack, sk = pieces[0:2]
        sk = sk.split(",") #pieces can be [""], ["2","3"]
        return cum_ack,sk


    def handle_timeout(self):
        for packet in self.packet_cached:
            self.send(packet)


    def handle_new_ack(self, ack):
        self.sack_list = []
        self.sack_retrans = False
        self.sack_list_copy = []
        move_size = ack - self.window[0]
        if self.msg_type == 'end':
            for i in range(1, move_size + 1):
                self.seqno += 1
                self.window.pop(0)
                self.window.append(self.seqno)
                return
        for i in range(1, move_size + 1):
            self.seqno += 1
            self.window.pop(0)
            self.packet_cached.pop(0)

            self.window.append(self.seqno)
            #initialize the sending packet
            msg = ""
            if self.file_read:
                msg = self.infile.read(self.data_size)
            else:
                msg = raw_input("Message:")

            self.msg_type = 'data'
            if self.seqno == 0:
                self.msg_type = 'start'
            if msg == "":
                self.msg_type = 'end'
            if msg == "done":
                self.msg_type = 'end'

            packet = self.make_packet(self.msg_type, self.seqno, msg)
            self.send(packet)
            self.packet_cached.append(packet)


            #print "send: %s" % packet
            if self.msg_type == 'end':
                if self.end_seqno is None:
                    self.end_seqno = self.seqno
                    return


    def handle_dup_ack(self, ack):
        self.handle_timeout()

    def log(self, msg):
        if self.debug:
            print msg


'''
This will be run if you run this script from the command line. You should not
change any of this; the grader may rely on the behavior here to test your
submission.
'''
if __name__ == "__main__":
    def usage():
        print "BEARS-TP Sender"
        print "-f FILE | --file=FILE The file to transfer; if empty reads from STDIN"
        print "-p PORT | --port=PORT The destination port, defaults to 33122"
        print "-a ADDRESS | --address=ADDRESS The receiver address or hostname, defaults to localhost"
        print "-d | --debug Print debug messages"
        print "-h | --help Print this usage message"
        print "-k | --sack Enable selective acknowledgement mode"

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                               "f:p:a:dk", ["file=", "port=", "address=", "debug=", "sack="])
    except:
        usage()
        exit()

    port = 33122
    dest = "localhost"
    filename = None
    debug = False
    sackMode = False

    for o,a in opts:
        if o in ("-f", "--file="):
            filename = a
        elif o in ("-p", "--port="):
            port = int(a)
        elif o in ("-a", "--address="):
            dest = a
        elif o in ("-d", "--debug="):
            debug = True
        elif o in ("-k", "--sack="):
            sackMode = True

    s = Sender(dest, port, filename, debug, sackMode)
    try:
        s.start()
    except (KeyboardInterrupt, SystemExit):
        exit()
