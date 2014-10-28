from sim.api import *
from sim.basics import *

'''
Create your distance vector router in this file.
'''
class DVRouter (Entity):
    def __init__(self):
        # Add your code here!

        #forwarding table: {key: value} --> {dest: [dist, next router to go]}
        self.forwardingTable = {}

        #neighbor table: {key: value} --> {neighborRouter: [dist, port no.]}
        self.neighbors = {}

        pass

    def handle_rx (self, packet, port):
        # Add your code here!
        if isinstance(packet, RoutingUpdate):
            self.handle_routing_update_packet(packet, port)

        elif isinstance(packet, DiscoveryPacket):
            self.handle_discovery_packet(packet, port)

        else:
            self.handle_other_packet(packet, port)


    def handle_routing_update_packet(self, packet, port):
        #print("hello update")
        source = packet.src

        #create a update info to be sent to others
        update_to_send = RoutingUpdate()
        update_to_send.src = self

        if self.neighbors[source][0] == float("inf"):
            for local_dest in self.forwardingTable.keys():
                if self.forwardingTable[local_dest][1] == source:
                    self.forwardingTable[local_dest][0] = float("inf")
                    update_to_send.add_destination(local_dest, float("inf"))

        for dest in packet.all_dests():
            #if the dest is itself, no need to update anything
            if dest != self:
                if dest not in self.forwardingTable.keys():
                    self.forwardingTable[dest] = [self.neighbors[source][0] + packet.get_distance(dest), source]
                    update_to_send.add_destination(dest, self.forwardingTable[dest][0])

                else:
                    if packet.get_distance(dest) == float("inf"):
                        #if self.forwardingTable[dest] != float("inf"):
                        if (isinstance(dest, DVRouter) and self in dest.neighbors.keys()) or (dest in self.neighbors.keys()):
                            continue
                        else:
                            self.forwardingTable[dest][0] = float("inf")
                            update_to_send.add_destination(dest, float("inf"))
                    #if the current dist to dest is greater
                    if self.forwardingTable[dest][0] > packet.get_distance(dest) + self.neighbors[source][0]:
                        self.forwardingTable[dest][0] = packet.get_distance(dest) + self.neighbors[source][0]
                        if self.forwardingTable[dest][0] >= 50:
                            self.forwardingTable[dest][0] = float("inf")
                        self.forwardingTable[dest][1] = source
                        update_to_send.add_destination(dest, self.forwardingTable[dest][0])

                    #if the current dist to dest is equal, select the smallest port no.
                    elif self.forwardingTable[dest][0] == packet.get_distance(dest) + self.neighbors[source][0]:
                        if self.neighbors[source][1] < self.neighbors[self.forwardingTable[dest][1]][1]:
                            self.forwardingTable[dest][1] = source
                            update_to_send.add_destination(dest, self.forwardingTable[dest][0])


        if len(update_to_send.all_dests()) != 0:
            self.send(update_to_send, port, True)



    def handle_discovery_packet(self, packet, port):
        source = packet.src
        latency = packet.latency

        #create a update info to be sent to others
        update_to_send = RoutingUpdate()
        update_to_send.src = self

        #if the source of the packet is not in its table yet
        if source not in self.neighbors.keys():
            self.neighbors[source] = [latency, port]
            self.forwardingTable[source] = [latency, source]
            update_to_send.add_destination(source, latency)
        else:
            #the old latency of this link
            old_latency = self.neighbors[source][0]
            self.neighbors[packet.src] = [latency, port]
            for dest in self.forwardingTable.keys():
                #if source is a dest in the forwarding table
                #change its distance to new latency
                if source == dest:
                    self.forwardingTable[dest] = [latency, dest]
                    update_to_send.add_destination(source, latency)
                #if source is the next router to go for a dest in the forwarding table
                #update the distance
                if source == self.forwardingTable[dest][1]:
                    if packet.is_link_up:
                        change = latency - old_latency
                        self.forwardingTable[dest][0] += change
                    #if the link is down
                    else:
                        min_dis = float("inf")
                        next_router = source
                        for neigh in self.neighbors.keys():
                            if neigh != source:
                                if isinstance(neigh, DVRouter) and dest in neigh.forwardingTable.keys():
                                    if neigh.forwardingTable[dest][0] + self.neighbors[neigh][0] < min_dis:
                                        min_dis = neigh.forwardingTable[dest][0] + self.neighbors[neigh][0]
                                        next_router = neigh
                        self.forwardingTable[dest] = [min_dis, next_router]
                    update_to_send.add_destination(dest, self.forwardingTable[dest][0])
        if isinstance(source, DVRouter):
            for dest in source.forwardingTable.keys():
                if dest != self:
                    if dest in self.forwardingTable.keys():
                        if self.forwardingTable[dest][0] > source.forwardingTable[dest][0] + self.neighbors[source][0]:
                            self.forwardingTable[dest] = [source.forwardingTable[dest][0] + self.neighbors[source][0],
                                                          source]
                    else:
                        self.forwardingTable[dest] = [source.forwardingTable[dest][0] + self.neighbors[source][0],
                                                      source]
                    update_to_send.add_destination(dest, self.forwardingTable[dest][0])
        if len(update_to_send.all_dests()) > 0:
            self.send(update_to_send, None, True)


    def handle_other_packet(self, packet, port):
        source = packet.src
        dest = packet.dst
        print dest
        print self.forwardingTable[dest][0]
        if dest in self.forwardingTable.keys():
            packet.ttl -= 1
            if(self.forwardingTable[dest][0] >= 50):
                return
            self.send(packet, self.neighbors[self.forwardingTable[dest][1]][1], False)







