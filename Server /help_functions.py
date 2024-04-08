from const_numbers import *
from datetime import datetime
import sql_functions
import os
import Crypto.Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from base64 import b64decode
from Crypto.Util import Padding
import cksum

client_list = []
file_list = []
folder_name = 'Decrypted files'

def byte_to_int(data):
    return int.from_bytes(data, byteorder='little')

def int_to_byte(data, len):
    return data.to_bytes(len, byteorder='little')

def public_key_func(aes_key, pub_key):
    rsa_key = RSA.import_key(pub_key)  # convert pub_key bytes to key format
    cipher_rsa = Crypto.Cipher.PKCS1_OAEP.new(rsa_key)  # encrypt the key
    return cipher_rsa.encrypt(aes_key) #encrypt aes_key using the cipher_rsa

def start():
    sql_functions.create()
    for row in sql_functions.execute_clients():
        client_list.append(row)
    for row in sql_functions.execute_files():
        file_list.append(row)
    os.mkdir(folder_name, )

#regist new user
def registration(name, lastseen):
    c1 = sql_functions.insert_client(name, lastseen)
    return c1

#send str message
def send_message(conn, message, len_m):
    reply_data = bytearray(message, "utf-8")
    new_data = bytearray(len_m)
    for i in range(min(len(reply_data), len(new_data))):
        new_data[i] = reply_data[i]
    conn.sendall(new_data)

#send byte message
def write_byte(conn, data, max_size):
    size = len(data)
    sent = 0
    while sent < size:
        send_size = min(size - sent, max_size)
        send_data = data[sent:sent + send_size]
        if len(send_data) < max_size:
            send_data += bytearray(max_size - len(send_data))
        try:
            conn.send(send_data) # write to client
            sent += len(send_data)
        except:
            print(f"Failed to respond to {conn}")

def send_header(conn, code, payload_size):
    conn.sendall(int_to_byte(VERSION, VERSION_SIZE))
    conn.sendall(int_to_byte(code, CODE_SIZE))
    conn.sendall(int_to_byte(payload_size, PAYLOAD_SIZE_IN_BYTES))

def delete_files_created():
    for f in file_list:
        path = folder_name + '/' + f.file_name
        os.remove(path)
    os.rmdir(folder_name)
    os.remove('defensive.db')
