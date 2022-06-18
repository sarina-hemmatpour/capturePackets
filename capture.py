from scapy.all import *


#a = sniff(count=4)
#a.summary()


packets = rdpcap("C:/Users/almas/Documents/attack1.pcap")
length=len(packets)


#all packets
#for i in packets:
 #   i.show()

#the whole summary
print(packets)

#number off all packets
print(f"Number of all packets: {length}")


#percentageof tcp and udp packets
countTCP=0
countUDP=0

for i in range(0, len(packets)):
          pkt = packets[i]
          if (TCP in pkt):
                   countTCP+= 1
          elif (UDP in pkt):
                   countUDP+= 1

print(f"TCP packets= {(countTCP/length)*100}%")
print(f"UDP packets= {(countUDP/length)*100}%")

#number of all fragments ******************************



