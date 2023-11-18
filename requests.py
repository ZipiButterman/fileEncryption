from const_numbers import *
from help_functions import *
from datetime import datetime
import sql_functions
import os
import Crypto.Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from base64 import b64decode
from Crypto.Util import Padding
import cksum

def registration_request(conn, code, name):
    for c in client_list:
        if c.name == name: #client almost exists
            print(f'{name}, your request to register as a new user (request code: {code}) not accepted (name almost exists).')
            sql_functions.update_lastseen(c.cid, str(datetime.now()))
            send_header(conn, REGISTRATION_NOT_SUCCEED_ANSWER, 0)
            print('closing', conn)
            sel.unregister(conn)
            conn.close()
    print(f'{name}, your request to register as a new user (request code: {code}) accepted.')
    new_client = registration(name, str(datetime.now()))  # create new client with name, last_seen and uuid (created in the db)
    client_list.append(new_client)  # add client to client_list
    size_client_id = len(new_client.cid)
    send_header(conn, REGISTRATION_SUCCEED_ANSWER, size_client_id)  # send header (version, code, payload_size)
    write_byte(conn, new_client.cid, size_client_id)  # send payload - client id
    print(f'name: {name}. uuid (in hex): {new_client.cid.hex()}')

def send_pub_key_request(conn, code, name, pub_key):
    print(f'{name}, your request to send a public key (request code: {code}) accepted.')
    aes_key = Crypto.Random.get_random_bytes(AES_KEY_SIZE)  # create aes key
    encrypted_aes_key = public_key_func(aes_key, pub_key)
    lastseen = str(datetime.now())
    for c in client_list:
        if c.name == name:  # looking for current client. (name must be unique)
            c.public_key = pub_key
            c.aes = aes_key
            c.last_seen = lastseen
            sql_functions.add_pub_key(c.cid, pub_key)
            sql_functions.add_aes_key(c.cid, aes_key)
            sql_functions.update_lastseen(c.cid, lastseen)
            size = len(c.cid) + len(encrypted_aes_key)
            send_header(conn, GOT_PUB_KEY_SEND_ENCRYPTED_AES_ANSWER, size)  # send header (version, code, payload_size)
            write_byte(conn, c.cid, len(c.cid))
            write_byte(conn, encrypted_aes_key, len(encrypted_aes_key))

def reconnect_request(conn, code, name):
    find = False
    for c in client_list:
        if c.name == name:
            print(f'{name}, your request to reconnect (request code: {code}) accepted.')
            sql_functions.update_lastseen(c.cid, str(datetime.now()))  # last seen = current time
            encrypted_aes_key = public_key_func(c.aes, c.public_key)
            size = len(c.cid) + len(encrypted_aes_key)
            send_header(conn, VALID_RECONNECT_SEND_ENCRYPTED_AES_ANSWER, size)  # send header (version, code, payload_size)
            write_byte(conn, c.cid, len(c.cid))
            write_byte(conn, encrypted_aes_key, len(encrypted_aes_key))
            find = True
    if not find:
        print(f'{name}, your request to reconnect(request code: {code}) not accepted (name doesn\'t exist. regist from beinning.).')
        new_client = registration(name, str(datetime.now()))  # create new client with name, last_seen and uuid (created in the db)
        client_list.append(new_client)  # add client to client_list
        size_client_id = len(new_client.cid)
        send_header(conn, REGISTRATION_SUCCEED_ANSWER, size_client_id)  # send header (version, code, payload_size)
        write_byte(conn, new_client.cid, size_client_id)  # send payload - client id

def send_file_request(conn, code, client_id, file_name, file_content, content_size):
    path = folder_name + '/' + file_name
    f = open(path, "wb")
    file_exists = False
    for c in client_list:
        hex_id = c.cid.hex()
        if hex_id == client_id:
            cipher = AES.new(c.aes, AES.MODE_CBC, iv=bytes(AES_KEY_SIZE))
            content = Padding.unpad(cipher.decrypt(file_content), AES.block_size)
            f.write(content)
            crc = cksum.memcrc(content)
            sql_functions.update_lastseen(c.cid, str(datetime.now()))
            print(f'{c.name}, your request to send an encrypted file: {file_name} (request code: {code}) accepted.')
            for f in file_list:
                if f.cid == c.cid and f.file_name == file_name:
                    file_exists = True
                    if f.verified:
                        print(f'{c.name}, notice: {file_name} almost exists. change the old file with the new file')
            if not file_exists:
                new_file = sql_functions.insert_file(c.cid, file_name, path)
                file_list.append(new_file)
            send_header(conn, GOT_VALID_FILE_WITH_CRC_ANSWER, (CONTENT_FILE_SIZE + FILE_NAME_SIZE))
            conn.sendall(int_to_byte(content_size, CONTENT_FILE_SIZE))
            padding_file_name = file_name.ljust(FILE_NAME_SIZE)
            send_message(conn, padding_file_name, len(padding_file_name))
            write_byte(conn, c.cid, len(c.cid))
            conn.sendall(int_to_byte(crc, CRC_SIZE))

def valid_crc_request(conn, code, file_name, client_id):
    name = ''
    for c in client_list:
        if c.cid.hex() == client_id:
            name = c.name
    print(f'{name}, your request to send valid CRC (request code: {code}) for: "{file_name}" file accepted.')
    for f in file_list:
        if f.cid.hex() == client_id and f.file_name == file_name:
            f.verified = True
            sql_functions.update_file(f.cid, f.file_name, True)
            sql_functions.update_lastseen(f.cid, str(datetime.now()))
            print(f'{name}, The {file_name} file decoded successfuly. Good bye.')
            send_header(conn, GOT_MESSAGE_ANSWER, len(f.cid))
            write_byte(conn, f.cid, len(f.cid))

def invalid_crc_request(conn, code, file_name, client_id):
    name = ''
    for c in client_list:
        if c.cid.hex() == client_id:
            name = c.name
    print(f'server responded with an error: {name}, your request to send invalid CRC (request code: {code}) for: "{file_name}" file accepted. Try to send again.')
    for f in file_list:
        if f.cid.hex() == client_id and f.file_name == file_name:
            sql_functions.update_lastseen(f.cid, str(datetime.now()))
            sql_functions.update_file(f.cid, f.file_name, False)

def last_invalid_crc_request(conn, code, file_name, client_id):
    name = ''
    for c in client_list:
        if c.cid.hex() == client_id:
            name = c.name
    print(f'{name}, your request to send invalid CRC in the last time (request code: {code}) for: "{file_name}" file accepted. Exit.')
    for f in file_list:
        if f.cid.hex() == client_id and f.file_name == file_name:
            sql_functions.update_lastseen(f.cid, str(datetime.now()))
            sql_functions.delete_file(f.cid, f.file_name)
            path = folder_name + '/' + file_name
            os.remove(path)
    send_header(conn, GOT_MESSAGE_ANSWER, len(f.cid))
    write_byte(conn, f.cid, len(f.cid))
