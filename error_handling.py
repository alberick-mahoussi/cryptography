#!/usr/bin/python3
##
## EPITECH PROJECT, 2023
## B-CNA-500-PAR-5-1-cryptography-alberick.mahoussi
## File description:
## mypgp
##

import sys

def print_usage():
    print("USAGE")
    print("./mypgp [-xor | -aes | -rsa | -pgp] [-c | -d] [-b] KEY")
    print("the MESSAGE is read from standard input")
    print("DESCRIPTION")
    print("-xor computation using XOR algorithm")
    print("-aes computation using AES algorithm")
    print("-rsa computation using RSA algorithm")
    print("-pgp computation using both RSA and AES algorithm")
    print("-c MESSAGE is clear and we want to cipher it")
    print("-d MESSAGE is ciphered and we want to decipher it")
    print("-b block mode: for xor and aes, only works on one block")
    print("MESSAGE and KEY must be of the same size")
    print("-g P Q for RSA only: generate a public and private key")
    print("pair from the prime number P and Q")

def handle_error(message):
    print("Error:", message)
    sys.exit(1)
