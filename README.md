# python-stun-mock


why: I need a simple stun mock and I didn't find one. (maybe I am not looking hard enough)

what: based from [RFC5389](https://datatracker.ietf.org/doc/html/rfc5389) only implemented message type  0x0101 (Binding Success Response) with 3 attributes. 0x0001 (Mapped-Address), 0x8020 (XOR-Mapped-Address) IPv4 only; and 0x8022 (Software)

tested on python 3.10.2 on MacOS


```bash
$ python stun_mock.py -h

usage: STUN Mock

positional arguments:
  return_ipaddr    IP address to return

options:
  -h, --help       show this help message and exit
  --listen LISTEN  IP to listen. default: 127.0.0.1
  --port PORT      default port to listen
  ```


  mock_client.py is the client test script.