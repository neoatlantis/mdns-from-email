#!/usr/bin/env python3

import sys
from select import select
import os
import yaml
import sys
from socket import *

from dnslib import DNSRecord, DNSHeader, DNSQuestion, A, RR
from .email_client import EmailSearch




config = yaml.load(open(sys.argv[1], "r").read())

client = EmailSearch(config["email"], config["mdns"])
client.check_email()


def ip_frame_extract(buf):
    if buf[0] != 0x45: return

    ip_header = buf[:20]
    udp_packet = buf[20:]

    ip_from = "%d.%d.%d.%d" % tuple(ip_header[12:16])
    ip_dest = "%d.%d.%d.%d" % tuple(ip_header[16:20])

    if ip_dest != "224.0.0.251": return

    udp_srcport = (udp_packet[0] << 8) | udp_packet[1]
    udp_dstport = (udp_packet[2] << 8) | udp_packet[3]
    
    payload = udp_packet[8:]

    if udp_srcport != 5353: return

#    print(ip_from, udp_srcport, udp_dstport, payload.hex())

    return {
        "from": ip_from,
        "query": DNSRecord.parse(payload),
    }


def generate_ip_packet(udppayload):
    # IP header, 
    ip_prefix = binascii.unhexlify("45000042cd094000ff110c96c0a80067e00000fb")





udpsocket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)
udpsocket2 = socket(AF_INET, SOCK_DGRAM)
udpsocket2.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
udpsocket2.bind(("0.0.0.0", 5353))


while True:
    r, _, __ = select([udpsocket], [], [])
    
    data = udpsocket.recv(65535)
    
    extract = ip_frame_extract(data)
    if not extract: continue

    dns_query = extract["query"]
    dns_questions = [
        (e.qtype, str(e.qname).lower())
        for e in dns_query.questions
    ]

    the_question = None
    the_answer = None
    for question in dns_query.questions:
        if question.qtype != 1: continue
        
        query_domain = str(question.qname).lower()
        if query_domain not in client.ip_table: continue
        
        the_question = question
        the_answer = client.ip_table[query_domain]
        break

    if not the_question: continue

    # broadcast answer

    if len(client.ip_table.keys()) < 1:
        print("IP NOT AVAILABLE.")
        client.check_email()
        continue



    """
    The determination of whether a given record answers a given question is
    made using the standard DNS rules: the record name must match the question
    name, the record rrtype must match the question qtype unless the qtype is
    "ANY" (255) or the rrtype is "CNAME" (5), and the record rrclass must match
    the question qclass unless the qclass is "ANY" (255).  As with Unicast DNS,
    generally only DNS class 1 ("Internet") is used, but should client software
    use classes other than 1, the matching rules described above MUST be used.
        --- RFC6762
    """

    dns_answer = DNSRecord(
        DNSHeader(
            qr=1, aa=1, id=dns_query.header.id,
            rd=0, # recursion desired = 0
            ra=0, # recursion available = 0 
        ),
        a=RR(
            rname=the_question.qname,
            rtype=the_question.qtype,
            rclass=the_question.qclass | (1<<15), # 1<<15: cache-flush
            rdata=A(the_answer),
            ttl=10
        )
    ) 

    # send it out
    udpsocket2.sendto(dns_answer.pack(), ("224.0.0.251", 5353))

    print("Q" * 100)
    print(dns_query)
    print("A"*100)
    print(dns_answer)
    print("")
