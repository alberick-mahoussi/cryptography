#!/usr/bin/python3
##
## EPITECH PROJECT, 2023
## B-CNA-500-PAR-5-1-cryptography-alberick.mahoussi
## File description:
## mypgp
##

from error_handling import handle_error

sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

inv_sbox = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
]

rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,]

def bytes_to_hex_string(byte_list):
    return ''.join(format(byte, '02x') for byte in byte_list)

mix_columns_matrix = [
    [0x02, 0x03, 0x01, 0x01],
    [0x01, 0x02, 0x03, 0x01],
    [0x01, 0x01, 0x02, 0x03],
    [0x03, 0x01, 0x01, 0x02]
]

inv_mix_columns_matrix = [
    [0x0e, 0x0b, 0x0d, 0x09],
    [0x09, 0x0e, 0x0b, 0x0d],
    [0x0d, 0x09, 0x0e, 0x0b],
    [0x0b, 0x0d, 0x09, 0x0e]
]

def substitute_bytes(state, operation):
    if operation == "-c":
        return [sbox[b] for b in state]
    elif operation == "-d":
        return [inv_sbox[b] for b in state]
    pass

def shift_rows(state):
    num_rows = 4
    num_columns = len(state) // num_rows

    shifted_state = [0] * len(state)
    for row in range(num_rows):
        for col in range(num_columns):
            shifted_state[row * num_columns + col] = state[row * num_columns + (col + row) % num_columns]

    return shifted_state

def inv_shift_rows(state):
    num_rows = 4
    num_columns = len(state) // num_rows

    shifted_state = [0] * len(state)
    for row in range(num_rows):
        for col in range(num_columns):
            shifted_state[row * num_columns + col] = state[row * num_columns + (col - row) % num_columns]

    return shifted_state

def add_round_key(state, round_key):
    return [state[i] ^ round_key[i] for i in range(len(state))]

def multiply_mod(a, b):
    poly = 0x11B 
    def binary_multiply(x, y):
        result = 0
        while y > 0:
            if y & 1:
                result ^= x
            x <<= 1
            if x & (1 << 8):
                x ^= poly
            y >>= 1
        return result

    product = binary_multiply(a, b)
    while product & (1 << 8):
        product ^= poly

    return product

def mix_columns_multiply(column, operation):
    result = [0] * 16
    tmp = 0

    matrix = mix_columns_matrix

    if operation == "-d":
        matrix = inv_mix_columns_matrix
    for index in range(4):
        if (index != 0):
            tmp = tmp + 4
        for i in range(4):
            for j in range(4):
                result[i + tmp] ^= multiply_mod(column[j + tmp], matrix[i][j])
                    

    return result

def key_expansion(key):
    key_ring = [key]
    index = 0

    for i in range(0, 10):
        tmp = []
        temp = key_ring[i][:]
        key_ring.append([0,0,0,0,
                         0,0,0,0,
                         0,0,0,0,
                         0,0,0,0,])
        tmp = temp[12]
        temp[12] = temp[13]
        temp[12] = sbox[temp[12]]
        temp[13] = temp[14]
        temp[13] = sbox[temp[13]]
        temp[14] = temp[15]
        temp[14] = sbox[temp[14]]
        temp[15] = tmp
        temp[15] = sbox[temp[15]]

        index = 0
        for j in range(0, 4):
            if j == 0:
                key_ring[i + 1][j] = key_ring[i][j] ^ temp[12] ^ rcon[i]
                temp[12] = key_ring[i + 1][j]
                key_ring[i + 1][j + 1] = key_ring[i][j + 1] ^ temp[13] ^ 0x00
                temp[13] = key_ring[i + 1][j + 1]
                key_ring[i + 1][j + 2] = key_ring[i][j + 2] ^ temp[14] ^ 0x00
                temp[14] = key_ring[i + 1][j + 2]
                key_ring[i + 1][j + 3] = key_ring[i][j + 3] ^ temp[15] ^ 0x00
                temp[15] = key_ring[i + 1][j + 3]
            else:
                key_ring[i + 1][index] = key_ring[i][index] ^ temp[12]
                temp[12] = key_ring[i + 1][index]
                key_ring[i + 1][index + 1] = key_ring[i][index + 1] ^ temp[13]
                temp[13] = key_ring[i + 1][index + 1]
                key_ring[i + 1][index + 2] = key_ring[i][index + 2] ^ temp[14]
                temp[14] = key_ring[i + 1][index + 2]
                key_ring[i + 1][index + 3] = key_ring[i][index + 3] ^ temp[15]
                temp[15] = key_ring[i + 1][index + 3]
            index += 4

    return key_ring

def reorganize_data(data_list):
    organized_data = [
        data_list[0], data_list[4], data_list[8], data_list[12],
        data_list[1], data_list[5], data_list[9], data_list[13],
        data_list[2], data_list[6], data_list[10], data_list[14],
        data_list[3], data_list[7], data_list[11], data_list[15]
    ]
    return organized_data

def aes_encrypt_block(block, key, operation):
    num_rounds = 10

    state = block
    key_ring = key_expansion(key)

    state = add_round_key(state, key)

    for i in range(1, num_rounds):
        state = substitute_bytes(state, operation)
        state = reorganize_data(state)
        state = shift_rows(state)
        state = reorganize_data(state)
        state = (mix_columns_multiply(state, operation))
        state = add_round_key(state, key_ring[i])

    state = substitute_bytes(state, operation)
    state = reorganize_data(state)
    state = shift_rows(state)
    state = reorganize_data(state)
    state = add_round_key(state, key_ring[10])

    return state

def aes_decrypt_block(block, key, operation):
    num_rounds = 10
    index = 9

    state = block
    key_ring = key_expansion(key)

    state = add_round_key(state, key_ring[10])

    for i in range(1, num_rounds):
        state = reorganize_data(state)
        state = inv_shift_rows(state)
        state = reorganize_data(state)
        state = substitute_bytes(state, operation)
        state = add_round_key(state, key_ring[index])
        state = (mix_columns_multiply(state, operation))
        index -= 1

    state = reorganize_data(state)
    state = inv_shift_rows(state)
    state = reorganize_data(state)
    state = substitute_bytes(state, operation)
    state = add_round_key(state, key)

    return state

def divide_message(message):
    block_size = 16  # Taille d'un bloc en octets pour AES
    message_blocks = []

    # Conversion de la chaîne hexadécimale en bytes
    message_bytes = bytes.fromhex(message)

    # Découpage du message en blocs de la taille appropriée
    for i in range(0, len(message_bytes), block_size):
        block = message_bytes[i:i + block_size]
        # Si le bloc est plus court que la taille fixe, appliquez un padding
        if len(block) < block_size:
            block = block + bytes([block_size - len(block)] * (block_size - len(block)))

        message_blocks.append(block)

    return message_blocks


def aes_cipher(message, key, operation, block_mode):
    if len(key) < 31:
        handle_error("Invalid key size")
    key_block = [int(key[i:i+2], 16) for i in range(0, len(key), 2)]
    if (block_mode == False):
        crypted_hex = []
        message_blocks = divide_message(message)
        for block in message_blocks:
            block_int = [int(byte) for byte in block]
            if operation == "-c":
                encrypted_block = aes_encrypt_block(block_int, key_block, operation)
                crypted_hex.append(bytes_to_hex_string(encrypted_block))
                # print(encrypted_hex, end="")
            elif operation == "-d":
                decrypted_block = aes_decrypt_block(block_int, key_block, operation)
                crypted_hex.append(bytes_to_hex_string(decrypted_block))
            else:
                handle_error("Invalid AES operation")
        if operation == "-d":
            crypted_hex[-1] = crypted_hex[-1].rstrip('0a')
        for hex in crypted_hex:
            print(hex, end="")
        print("")
    elif (block_mode == True):
        block = [int(message[i:i+2], 16) for i in range(0, len(message), 2)]
        if operation == "-c":
            encrypted_block = aes_encrypt_block(block, key_block, operation)
            encrypted_hex = bytes_to_hex_string(encrypted_block)
            print(encrypted_hex)
        elif operation == "-d":
            decrypted_block = aes_decrypt_block(block, key_block, operation)
            decrypted_hex = bytes_to_hex_string(decrypted_block)
            print((decrypted_hex))
        else:
            handle_error("Invalid AES operation")
    else:
        handle_error("Invalid block mode")
    pass
