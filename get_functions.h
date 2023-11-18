#pragma once
#include "general.h"
#include <string>
#include <boost/endian.hpp>
#include <iostream>

void send_encrypted_file_to_server(std::string, uint8_t*);
std::string encrypt_file(std::string, std::string);
void send_not_success_message(uint8_t*);
void send_success_message(uint8_t*);
void send_abort_message(uint8_t*);
uint8_t* get_key_from_server(uint8_t[]);

#define PATH_SIZE 255
#define FILE_NAME_SIZE 255
#define ID_SIZE 16
#define VERSION_SIZE 1
#define PAYLOAD_SIZE 4
#define CONTENT_FILE_SIZE 4
#define CRC_SIZE 4
#define SEND_CRC 3
#define CODE_SIZE 2
#define VALID_CRC_REQUEST 1029
#define INVALID_RECONNECT_ANSWER 2106
#define GENERAL_ANSWER 2107

extern boost::asio::io_context io_context;
extern tcp::socket s;
extern tcp::resolver resolver;

extern std::string _aes_key;
extern std::string _priv_key;
uint32_t aes_size = 0;
int _trying_to_send_crc = 0;
unsigned long _crc = 0;
