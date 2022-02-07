#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
"""
stun test client to send request to stun_mock.py
"""
import random
import socket

ATTRIBUTE_ADDRESS = ['0001', '0004', '0005', '8020']
ATTRIBUTE_TEXT = ['8022']


def request(server='127.0.0.1', port=3478, source_port=12345):
    """ send stun binding request 0x0001
    """
    transaction_id = ''.join(
        random.choice('0123456789ABCDEF') for i in range(32))
    # send request 0001 with length=0 0000
    request_txt = '00010000' + transaction_id
    source_ip = '0.0.0.0'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((source_ip, source_port))
        sock.sendto(bytes.fromhex(request_txt), (server, port))
        data, _ = sock.recvfrom(2048)
    return data


def parse(data):
    """"
    parse response
    """
    msg_type = data[:2].hex()
    length = int(data[2:4].hex(), 16)
    magic = data[4:8].hex()
    transaction_id = data[8:].hex()

    print('message type', msg_type)
    print('message length', length)
    print('magic', magic)
    print('transaction id', transaction_id)

    attributes = data[20:-1]
    while attributes:
        attribute_type = attributes[0:2].hex()
        attribute_length = int(attributes[2:4].hex(), 16)
        print('attribute type:', attribute_type)
        print('\t', 'attribute length:', attribute_length)

        if attribute_type in ATTRIBUTE_ADDRESS:
            family = attributes[5]
            print('\t', 'attribute family:', family)
            port = int(attributes[6:8].hex(), 16)
            print('\t', 'attribute port:', port)
            if family == 1:
                ip_size = 4
            else:
                ip_size = 16
            ipaddr = socket.inet_ntoa(attributes[8:8+ip_size])
            print('\t', 'attribute IP:', ipaddr)
        elif attribute_type in ATTRIBUTE_TEXT:
            text = attributes[4:4+attribute_length].decode()
            print('\t', 'attribute text:', text)
        else:
            print('skip attribute type:', attribute_type)
        attributes = attributes[4+attribute_length:]


def main():
    """ entry point
    """
    data = request()
    print('reveived data:', data)
    print('received data len:', len(data))
    print()
    print()
    parse(data)


if __name__ == '__main__':
    main()
