#pragma once
#include "general.h"
#include <string>
#include <fstream>
#include <iostream>
#include <boost/endian.hpp>
#include "RSAWrapper.h"
#include "Base64Wrapper.h"

#define PATH_SIZE 255
#define NAME_SIZE 255
#define FILE_NAME_SIZE 255
#define INVALID_RECONNECT_ANSWER 2106
#define REGISTRATION_SUCCEED_ANSWER 2100
#define REGISTRATION_REQUEST 1025
#define RECONNECT_REQUEST 1027
#define VERSION 3
#define VERSION_SIZE 1
#define PAYLOAD_SIZE 4
#define CODE_SIZE 2
#define ID_SIZE 16

boost::asio::io_context io_context;
tcp::socket s(io_context);
tcp::resolver resolver(io_context);

std::string read_priv_file();
std::string regist();
std::string send_public_key(std::string);
std::string encrypt_file(std::string, std::string);
uint16_t get_header();
uint8_t* get_key_from_server(uint8_t[]);
std::vector <uint8_t> push_header_to_vector(std::vector <uint8_t>, int, int);
int reconnect(std::string);
void get_encrypted_public_key(std::string);
void send_encrypted_file_to_server(std::string, uint8_t*);
void create_priv_file(Base64Wrapper, std::string);
void create_me_file(Base64Wrapper, char[], std::string, uint8_t[]);
void write_to_server(std::vector <uint8_t>, int);
void connect_to_server();
std::string toHexStr(const uint8_t*, int);
