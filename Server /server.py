import os
import Crypto.Random
import struct
import selectors
import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import sql_functions
from base64 import b64decode
from Crypto.Util import Padding
import cksum
from datetime import datetime
from const_numbers import *
from help_functions import *
from requests import *

sel = selectors.DefaultSelector()

def accept(sock, mask):
    conn, addr = sock.accept()
    print('accepted. from', addr)
    conn.setblocking(False)
    sel.register(conn, selectors.EVENT_READ, read)

with open('port.info', 'r') as f:
    port_number = f.readlines()
    if port_number == '':
        port_number = DEFAULT_PORT

def read(conn, mask):
    #get header:
    byte_client_id = conn.recv(CLIENT_ID_SIZE) #get client id
    byte_version = conn.recv(VERSION_SIZE) #get client version
    byte_code = conn.recv(CODE_SIZE) #get request code
    byte_payload = conn.recv(PAYLOAD_SIZE_IN_BYTES) #get payload size
    client_id = byte_client_id.hex() #convert id to hex
    version = byte_to_int(byte_version) #convert version to int
    code = byte_to_int(byte_code) #convert code to int
    payload = byte_to_int(byte_payload) #convert payload to int
    if not byte_client_id: #client didn't send data
        print('closing server for current user.')
        sel.unregister(conn)
        conn.close()
    # first time client register
    if code == REGISTRATION_REQUEST:
        name = conn.recv(NAME_SIZE).decode('utf-8').replace('\0', '')  # get name of client
        registration_request(conn, code, name)
    #get public key
    elif code == SEND_PUB_KEY_REQUEST:
        name = conn.recv(NAME_SIZE).decode('utf-8').replace('\0', '') #get name of client
        pub_key = conn.recv(PUBLIC_KEY_SIZE) #get public key
        send_pub_key_request(conn, code, name, pub_key)
    elif code == RECONNECT_REQUEST:
        name = conn.recv(NAME_SIZE).decode('utf-8').replace('\0', '')  # get name of client
        reconnect_request(conn, code, name)
    elif code == SEND_FILE_REQUEST:
        byte_content_size = conn.recv(PAYLOAD_SIZE_IN_BYTES)
        file_name = conn.recv(FILE_NAME_SIZE).decode('utf-8').replace('\0', '')
        content_size = byte_to_int(byte_content_size)
        size = content_size
        file_content = b''
        while content_size > MAX_SIZE:
            content_size = content_size - MAX_SIZE
            file_content += conn.recv(MAX_SIZE)
        file_content += conn.recv(content_size)
        send_file_request(conn, code, client_id, file_name, file_content, size)
    elif code == VALID_CRC_REQUEST:
        file_name = conn.recv(FILE_NAME_SIZE).decode('utf-8').replace('\0', '')
        valid_crc_request(conn, code, file_name, client_id)
    elif code == INVALID_CRC_REQUEST:
        file_name = conn.recv(FILE_NAME_SIZE).decode('utf-8').replace('\0', '')
        invalid_crc_request(conn, code, file_name, client_id)
    elif code == LAST_INVALID_CRC_REQUEST:
        file_name = conn.recv(FILE_NAME_SIZE).decode('utf-8').replace('\0', '')
        last_invalid_crc_request(conn, code, file_name, client_id)

if __name__ == "__main__":
    start()
    try:
        sock = socket.socket()
        sock.bind(('', int("".join(port_number))))
        sock.listen(100)
        sock.setblocking(False)
        sel.register(sock, selectors.EVENT_READ, accept)
        while True:
            events = sel.select()
            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask)
    except:
        delete_files_created()
        print('Socket closed suddenly. exit.')
        exit(1)
    finally:
        sock.close()
