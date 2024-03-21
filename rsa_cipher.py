#!/usr/bin/python3
##
## EPITECH PROJECT, 2023
## B-CNA-500-PAR-5-1-cryptography-alberick.mahoussi
## File description:
## mypgp
##

from error_handling import handle_error

def int_to_little_endian(n):
    hex_string = hex(n)[2:]  # Convertir en hexadécimal et retirer le préfixe '0x'
    hex_string = hex_string.rjust(len(hex_string) + len(hex_string) % 2, '0')  # Assurer une longueur paire
    little_endian = ''.join(reversed([hex_string[i:i+2] for i in range(0, len(hex_string), 2)]))
    return little_endian

def encrypt(message, public_key):
    e, n = public_key.split('-')
    e = int(e, 16)
    n = int(n, 16)
    n = int_to_little_endian(n)
    e = int_to_little_endian(e)
    message = int(message, 16)
    message = int_to_little_endian(message)
    message = int(message, 16)
    e = int(e, 16)
    n = int(n, 16)

    cipher_text = pow(message, e, n)
    return int_to_little_endian(cipher_text)

def decrypt(message, private_key):
    d, n = private_key.split('-')
    message = int(message, 16)
    message = int_to_little_endian(message)
    message = int(message, 16)
    n = int(n, 16)
    d = int(d, 16)
    n = int_to_little_endian(n)
    d = int_to_little_endian(d)
    n = int(n, 16)
    d = int(d, 16)


    cipher_text = pow(message, d, n)
    return int_to_little_endian(cipher_text)

def rsa_cipher_func(message, key, operation):
    if operation == "-c":
        print(encrypt(message, key))
    elif operation == "-d":
        print(decrypt(message, key))
    else:
        handle_error("Invalid XOR operation")
    pass
