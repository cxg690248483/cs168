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
        if sackMode:
            raise NotImplementedError #remove this line when you implement SACK

    def handle_response(self,response_packet):
        if Checksum.validate_checksum(response_packet):
            print "recv: %s" % response_packet
            received_packet_split = self.split_packet(response_packet)
            return received_packet_split
        else:
            print "recv: %s <--- CHECKSUM FAILED" % response_packet
    # Main sending loop.
    def start(self):
        data_size = 1200
        timeout = 0.5
        window_size = 5
        seqno = 0
        window = []
        msg_type = None
        #msg = self.infile.read(data_size)
        file_read = True
        if self.infile == sys.stdin:
            file_read = False

        for i in range(0, 5):
            msg = ""
            if file_read:
                msg = self.infile.read(data_size)
            else:
                msg = raw_input("Message:")
            msg_type = 'data'
            if seqno == 0:
                msg_type = 'start'
            if msg == "":
                msg_type = 'end'
            if msg == "done":
                msg_type = 'end'
        
            packet = self.make_packet(msg_type, seqno, msg)
            self.send(packet)
            
            window.append(i)
            seqno += 1

            print "send: %s" % packet
            if msg_type == 'end':
                break
            #print "send: %s" % packet
        
        #last_received_ack = 0
        dup_ack_num = 0
        while not msg_type == 'end':
            response = self.receive(timeout)
            if(response == None):
                print "timeout dude!"
                seqno = window[0]
            received_packet = self.handle_response(response)
            ack = int(received_packet[1])
            if ack < window[0]:
                continue
            if ack == window[0]:
                dup_ack_num += 1
                continue
            else:
                print seqno
                move_size = ack - window[0]
                for i in range(1, move_size + 1):
                    seqno += i
                    window.pop(0)
                    window.append(seqno)
                    
                    #initialize the sending packet
                    msg = ""
                    if file_read:
                        msg = self.infile.read(data_size)
                    else:
                        msg = raw_input("Message:")
                        msg_type = 'data'
                    if seqno == 0:
                        msg_type = 'start'
                    if msg == "":
                        msg_type = 'end'
                    if msg == "done":
                        msg_type = 'end'
                            
                    packet = self.make_packet(msg_type, seqno, msg)
                    self.send(packet)
                    print "send: %s" % packet





    def handle_timeout(self):
        pass

    def handle_new_ack(self, ack):
        pass

    def handle_dup_ack(self, ack):
        pass

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
