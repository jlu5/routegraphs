#!/usr/bin/env python3
import socket

def get_cidr(network_binary: bytes, prefix_length: int) -> str:
    network = socket.inet_ntop(
            socket.AF_INET6 if len(network_binary) == 16 else socket.AF_INET,
            network_binary)
    cidr = f'{network}/{prefix_length}'
    return cidr
