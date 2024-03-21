#!/usr/bin/python3
##
## EPITECH PROJECT, 2023
## B-CNA-500-PAR-5-1-cryptography-alberick.mahoussi
## File description:
## mypgp
##

import random

# Function to check if a number is prime
def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def little_endian(hex_value):
    hex_string = str(hex_value)

    if hex_string.startswith('0x') or hex_string.startswith('0X'):
        hex_string = hex_string[2:]
    if len(hex_string) % 2 != 0:
        hex_string = '0' + hex_string
    little_endian_value = ''.join(reversed([hex_string[i:i+2] for i in range(0, len(hex_string), 2)]))

    return little_endian_value
def generate_keys(p, q):
    if p == q:
        raise ValueError("The numbers cannot be equal.")

    n = p * q

    phi = (p - 1) * (q - 1)

    e = random.randrange(1, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(1, phi)

    d = mod_inverse(e, phi)

    return (little_endian(e), little_endian(hex(n))), (little_endian(d), little_endian(hex(n)))

def bytes_to_hex_string(byte_list):
    return ''.join(format(byte, '02x') for byte in byte_list)

def rsa_generate_keys(p, q):
    p = int(p, 16)
    q = int(q, 16)
    public_key, private_key = generate_keys(p, q)

    print("Public Key: ", public_key[0], "-", public_key[1], sep="")
    print("Private Key: ", private_key[0], "-", private_key[1], sep="")
    pass
