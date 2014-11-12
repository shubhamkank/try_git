## Import Scapy module
from scapy.all import *
## Create a Packet Count var
packetCount = 0
## Define our Custom Action function
def customAction(packet):
    global packetCount
    packetCount += 1
    return packet.summary()
## Setup sniff, filtering for IP traffic
sniff(prn=customAction)