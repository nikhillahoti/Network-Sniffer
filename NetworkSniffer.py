# Packet sniffer in python for Linux
# Sniffs only incoming TCP packet and tracks the number of requests from a particular ip within a span of 1 minute
# If the number of requests is more than a specified threshold then the ip address is blocked and this activity is
# notified to be checked

import socket, sys
from struct import *
import threading
import time
import paramiko

# global hashmap function which keeps track of the number of requests from an ip address
IpAddress_Map = {'ip': 0}

# function which calls the remote linux machine using the paramiko library using the ssh connection
def paramikoConnection():
    RemotePC = paramiko.SSHClient()
    RemotePC.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    RemotePC.connect('10.0.2.4', username='seed', password='dees')
    return  RemotePC

# function to block the ip address after a threshold is breached.
# An entry into the iptables is made to block the ip ipAddress
def blockIPAddresses(IPAddress):
    RemotePC = paramikoConnection()
    stdin, stdout, stderr = RemotePC.exec_command('iptables -A INPUT -s ' + str(IPAddress) + ' -j DROP')
    RemotePC.close()

# New thread is created in the background which checks after every minute if a particular ip address has requested
# more than a threshold
def check_for_blockedIpAddress():
    while 1:
        threshold = 30
        global IpAddress_Map
        for ipAddress in IpAddress_Map:
            count_of_visits = IpAddress_Map[ipAddress]
            if count_of_visits > threshold:
                print("IP Address to be blocked is " + ipAddress)
                blockIPAddresses(ipAddress)
        IpAddress_Map = {'ip': 0}
        time.sleep(60)  # create an INET, STREAMing socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error, msg:
    print('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
    sys.exit()

# New thread is created to allow checking for threshold breach in the background when the main thread is working on
# on scanning new incoming packets
hashThread = threading.Thread(target=check_for_blockedIpAddress)
hashThread.start()

# receive a packet
while True:
    packet = s.recvfrom(65565)

    # packet string from tuple
    packet = packet[0]

    # ip header forms only the first 20 characters
    ip_header = packet[0:20]

    # unpacking the packet depending on the type of the value
    iph = unpack('!BBHHHBBH4s4s', ip_header)

    # Fetching the source and destination address of the ip packet
    s_addr = socket.inet_ntoa(iph[8]);

    # checking if the ip address is present in out hash-map
    if s_addr in IpAddress_Map:
        value = IpAddress_Map[str(s_addr)]
        value += 1
        IpAddress_Map[str(s_addr)] = value
    else:
        IpAddress_Map[str(s_addr)] = 1
        #  print(" The count for " + str(s_addr) + " is " + str(IpAddress_Map[s_addr]))
