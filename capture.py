
from sys import flags
from telnetlib import IP
from scapy.all import *


#a = sniff(count=4)
#a.summary()


packets = rdpcap("C:/Users/Lenovo/Downloads/Compressed/trace4.pcap")
length=len(packets)


#show fields:
#for i in packets:
#    i.show()


# packets[0].show()

#the whole summary
print(packets)


#number off all packets
print(f"\nNumber of all packets: {length}")


#percentage of tcp and udp packets
countTCP=0
countUDP=0

for i in range(0, len(packets)):
    pkt = packets[i]
    if (TCP in pkt):
        countTCP+= 1
    elif (UDP in pkt):
        countUDP+= 1

print(f"\nTCP packets= {(countTCP/length)*100}%")
print(f"UDP packets= {(countUDP/length)*100}%")

#number of fragmented datagrams: **

print("\n**Number of fragmented datagrams:**")

DFs = 0
for i in packets[IP]:
    if i.flags==2: #DF  010 i.flags=="DF"
        DFs+=1

fragmented = length-DFs

print(f"\nNumber of fragmented datagrams= {fragmented}")

#scanning **
srcIP=input('\n\n146.137.96.1Enter the source IP:  ')

# srcS=[]

countS=0
countSA = 0

for i in packets[IP]:
    if i.src == srcIP:
        if i.flags == 18:
            countSA +=1

        if i.flags == 2:
            countS +=1


print(f"\nSYN/ACK: {countSA}")
print(f"SYN: {countS}")

if countSA!=0:
    if countS/countSA>3:
        print(f"\nWARNING _ scanning attack !!! {countS/countSA>3}")
else: 
    print('\n no attack detected')