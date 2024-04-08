#pragma once
#include "general.h"
#include <string>
#include <fstream>
#include <boost/endian.hpp>
#include <vector>

#define NAME_SIZE 255
#define FILE_NAME_SIZE 255
#define ID_SIZE 16
#define VERSION_SIZE 1
#define PAYLOAD_SIZE 4
#define VERSION 3
#define CODE_SIZE 2
#define PUBLIC_KEY_SIZE 160
#define SEND_PUB_KEY_REQUEST 1026
#define CONTENT_FILE_SIZE 4
#define SEND_FILE_REQUEST 1028
#define VALID_CRC_REQUEST 1029
#define INVALID_CRC_REQUEST 1030
#define LAST_INVALID_CRC_REQUEST 1031

extern boost::asio::io_context io_context;
extern tcp::socket s;
extern tcp::resolver resolver;

extern char _name_line[NAME_SIZE];
extern char _file_name[FILE_NAME_SIZE];
extern std::string _priv_key;

std::string HexToBytes(const std::string&);
std::vector <uint8_t> push_header_to_vector(std::vector <uint8_t>, int, int);
void write_to_server(std::vector <uint8_t>, int);
void get_crc(int);
void get_answer(uint16_t);

