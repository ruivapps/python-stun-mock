#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
"""stun server mock

https://datatracker.ietf.org/doc/html/rfc5389
"""
import argparse
import asyncio
import logging
import os
import socket

MAGIC_COOKIE = 0x2112A442

RESPONSE = {'ipaddr': None}

DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'

# pylint: disable=invalid-name
logger = logging.getLogger()


def setup_stream_logging(debug: bool) -> None:
    """ setup logging
    """
    handler = logging.StreamHandler()
    logformat = '%(asctime)s %(filename)s %(funcName)s %(levelname)s [%(lineno)s] ::: %(message)s'
    level = logging.DEBUG if debug else logging.INFO
    handler.setLevel(level)
    logger.setLevel(level)
    handler.setFormatter(logging.Formatter(logformat))
    logger.addHandler(handler)


def parse_header(header: bytes) -> list[str, int, str, str]:
    """ parse stun header
    """
    message_type = header[:2].hex()
    message_length = int(header[2:4].hex(), 16)
    magic_cookie = header[4:8].hex()
    transaction_id = header[8:20].hex()
    return message_type, message_length, magic_cookie, transaction_id


def create_header(transaction_id: str, length: int) -> bytes:
    '''
    20 byte header: type + length + magic_id + transaction_it

        * 16 bits [2 bytes] stun message type always starts with 00
        * 16 bits [2 bytes] length contain the size in bytes of the message
            not including the 20-byte STUN header
        * 32 bits [4 bytes] magic cookie with a fix value: 0x2112A442
        * 96 bits [12 bytes] transaction id used to uniquely identify STUN transactions
    '''
    message_type = bytes.fromhex('0101')
    messsage_length = bytes.fromhex(format(length, '04x'))
    magic_cookie = bytes.fromhex(format(MAGIC_COOKIE, "04x"))
    transaction = bytes.fromhex(transaction_id)
    return message_type + messsage_length + magic_cookie + transaction


def create_attribute(ipaddr: str, port: int) -> bytes:
    '''
    STUN attributes is TLV (Type-Length-Value) encoded and padded to a multiple of 4 bytes
        * 16 bits [2 bytes] attribute type
        * 16 bits [2 bytes] length (length of the value prior to padding, measured in bytes)
        * 32 bits [4 bytes] value boundary
    '''

    attribute_type = bytes.fromhex('0001')
    attribute_value = create_mapped_address(ipaddr, port)
    attribute_length = bytes.fromhex(format(len(attribute_value), '04x'))
    mapped_address = attribute_type + attribute_length + attribute_value

    attribute_type = bytes.fromhex('8020')
    attribute_value = create_xor_mapped_address(ipaddr, port)
    attribute_length = bytes.fromhex(format(len(attribute_value), '04x'))
    xor_mapped_address = attribute_type + attribute_length + attribute_value

    attribute_type = bytes.fromhex('8022')
    attribute_value = create_software()
    attribute_length = bytes.fromhex(format(len(attribute_value), '04x'))
    software = attribute_type + attribute_length + attribute_value

    return mapped_address + xor_mapped_address + software


def create_mapped_address(ipaddr: str, port: int) -> bytes:
    """
    The MAPPED-ADDRESS attribute indicates a reflexive transport address of the client
    The first 8 bits must be set to 0 (align 32-bit boundaries)

        * 8 bits [1 byte] zero (align 32-bit boundaries)
        * 8 bits [1 byte] family
            - 0x01: IPv4
            - 0x02: IPv6
        * 16 bits [2 bytes] port
        * 32/128 bits [4/16 bytes] IPv4/IPv6 address
    """
    zero = bytes.fromhex('00')
    family = bytes.fromhex('01')
    port_byte = bytes.fromhex(format(port, '04x'))
    ipaddr_byte = socket.inet_aton(ipaddr)
    return zero + family + port_byte + ipaddr_byte


def create_xor_mapped_address(ipaddr: str, port: int) -> bytes:
    """
    X-Port is computed by taking the mapped port in host byte order,
    XOR'ing it with the most significant 16 bits of the magic cookie

    for IPv4:  X-Address is computed by taking the mapped IP address
        in host byte order, XOR'ing it with the magic cookie


    # to get ipv6, need to take another parameter for transaction ID
    IPv6, X-Address is computed by taking the mapped IP address in host byte order,
        XOR'ing it with the concatenation of the magic cookie and the 96-bit transaction ID
    """

    zero = bytes.fromhex('00')
    family = bytes.fromhex('01')
    xor_port = port ^ int(format(MAGIC_COOKIE, "04x")[:4], 16)
    xor_port_byte = bytes.fromhex(format(xor_port, '04x'))
    xor_ip = int(socket.inet_aton(ipaddr).hex(), 16) ^ MAGIC_COOKIE
    xor_ip_byte = bytes.fromhex(format(xor_ip, "04x"))
    return zero + family + xor_port_byte + xor_ip_byte


def create_software() -> bytes:
    """
    software string
        * 32 bits [4 bytes] value boundary
    """
    text = 'Python Stun Mock Server v1.0'
    hex_text = text.encode('utf-8').hex()
    pad = len(hex_text) % 4 and 4 - len(hex_text) % 4
    return bytes.fromhex(hex_text) + pad * bytes.fromhex('00')


class AsyncUDPServer(asyncio.Protocol):
    """
    stun request handler
    """
    # pylint: disable=attribute-defined-outside-init

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        """
        stun udp handler
        """
        logger.info('received data from: %s', addr)
        logger.debug('data is: %s', data)
        message_type, message_length, magic_cookie, transaction_id = parse_header(
            data)
        print(type(message_type), type(message_length),
              type(magic_cookie), type(transaction_id))
        logger.debug('received stun message type: %s', message_type)
        logger.debug('the stun length is: %s', message_length)
        logger.debug('the magic cookie is: %s', magic_cookie)
        logger.debug('the transaction id: %s', transaction_id)
        if message_type not in ['0001']:
            logger.warning('request %s not supported', message_type)
            self.transport.sendto(b"sorry. not supported", addr)
            return
        ipaddr, port = addr
        ipaddr = RESPONSE.get('ipaddr', ipaddr) or ipaddr
        attribute = create_attribute(ipaddr, port)
        header = create_header(transaction_id, len(attribute))
        logger.debug('header: %s', header)
        logger.debug('attribute: %s', attribute)
        logger.info('offer client with IP: %s port %s', ipaddr, port)
        self.transport.sendto(header+attribute, addr)


def main():
    """ entry point
    """
    parser = argparse.ArgumentParser(usage='STUN Mock')
    parser.add_argument('--listen', default='127.0.0.1',
                        help='IP to listen. default: 127.0.0.1')
    parser.add_argument('--port', default=3478, type=int,
                        help='default port to listen')
    parser.add_argument('return_ipaddr', nargs='?',
                        help='IP address to return')
    options = parser.parse_args()
    setup_stream_logging(DEBUG)
    logger.info(options)
    if options.return_ipaddr:
        RESPONSE['ipaddr'] = options.return_ipaddr

    logger.info('stun mock server lisetn on %s port %s',
                options.listen, options.port)
    loop = asyncio.new_event_loop()
    instance = loop.create_datagram_endpoint(
        AsyncUDPServer, local_addr=(options.listen, options.port))
    transport, _ = loop.run_until_complete(instance)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        logger.info("\nshutdown server")
    finally:
        transport.close()
        loop.close()


if __name__ == '__main__':
    main()
