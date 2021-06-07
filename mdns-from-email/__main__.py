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







udpsocket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)
udpsocket2 = socket(AF_INET, SOCK_DGRAM)
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
    for question in dns_query.questions:
        if question.qtype != 1: continue
        if str(question.qname).lower() != "deuchi-cn.local.": continue
        the_question = question
        break

    if not the_question: continue

    # broadcast answer

    if not client.ip:
        print("CHINA IP NOT AVAILABLE.")
        client.check_email()
        continue

    dns_answer = DNSRecord(
        DNSHeader(qr=1, aa=1, ra=1, id=dns_query.header.id),
        q=DNSQuestion(the_question.qname),
        a=RR(
            the_question.qname,
            rdata=A(client.ip),
            ttl=20
        )
    ) 

    # send it out
    udpsocket2.sendto(dns_answer.pack(), ("224.0.0.251", 5353))
    print(dns_answer)
