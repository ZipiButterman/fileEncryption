#include "get_functions.h"

/*this function gets the encrypted public key from server and send it to 'encrypt_file' function to encrypt the file with it*/
void get_encrypted_public_key(std::string private_key) 
{
	uint8_t id_char[ID_SIZE] = { '\0' };
	uint8_t* id = get_key_from_server(id_char); /*get data from server*/
	for (int i = 0; i < ID_SIZE; i++)
	{
		id_char[i] = id[i];
	}
	std::string encrypt = encrypt_file(_aes_key, private_key);
	send_encrypted_file_to_server(encrypt, id_char);
}

/*this function gets each time the current header from server*/
uint16_t get_header() 
{
	boost::endian::little_uint8_buf_t buff_version;
	boost::endian::little_uint16_buf_t buff_code;
	boost::endian::little_uint32_buf_t buff_payload_size;
	try 
	{
		size_t version_length = boost::asio::read(s, boost::asio::buffer(buff_version.data(), VERSION_SIZE));
		size_t code_length = boost::asio::read(s, boost::asio::buffer(buff_code.data(), CODE_SIZE));
		size_t payload_size_length = boost::asio::read(s, boost::asio::buffer(buff_payload_size.data(), PAYLOAD_SIZE));
	} 
	catch (std::exception& e) 
	{
		std::cerr << "Exception: " << e.what() << "\n";
	}
	uint8_t version = buff_version.value();
	uint16_t code = buff_code.value();
	uint32_t size = buff_payload_size.value();
	if (code == GENERAL_ANSWER)
	{
		std::cout << "server got an unexcepted error (code is: )." << code << "exit.\n";
		exit(1);
	}
	std::cout << "server answer code is: " << code << std::endl;
	aes_size = size; /*save size to know the aes key size (size - ID_SIZE)*/
	return code;
}

/*this functios gets the aes key from server*/
uint8_t* get_key_from_server(uint8_t id[ID_SIZE]) 
{
	uint16_t answer_code = get_header();
	if (answer_code == INVALID_RECONNECT_ANSWER) /*client name not exists in the db in the server*/
	{ 
		std::cout << "client not exists. regist from beginning." << std::endl;
		return NULL;
	}
	try 
	{
		size_t reply_length = boost::asio::read(s, boost::asio::buffer(id, ID_SIZE));
		std::string reply_aes(aes_size - ID_SIZE, '\0');
		size_t reply_length2 = boost::asio::read(s, boost::asio::buffer(reply_aes.data(), reply_aes.size()));
		std::cout << "server sent the aes key with successful." << std::endl;
		_aes_key = reply_aes;
	} 
	catch (std::exception& e) 
	{
		std::cerr << "Exception: " << e.what() << "\n";
	}
	return id;
}

/*this function gets crc from server and compare s it to the crc in client. if it's not equal, the server try to send 3 times and the finish*/
void get_crc(int send_crc) 
{
	char file_name[PATH_SIZE] = { '\0' };
	uint8_t reply_id[ID_SIZE] = { '\0' };
	uint16_t code = get_header();
	uint32_t crc = 0;
	boost::endian::little_uint32_buf_t buff_file_content_size;
	boost::endian::little_uint32_buf_t buff_crc;
	try 
	{
		size_t content_len = boost::asio::read(s, boost::asio::buffer(buff_file_content_size.data(), CONTENT_FILE_SIZE));
		size_t file_len = boost::asio::read(s, boost::asio::buffer(file_name, FILE_NAME_SIZE));
		size_t id_len = boost::asio::read(s, boost::asio::buffer(reply_id, ID_SIZE));
		size_t crc_len = boost::asio::read(s, boost::asio::buffer(buff_crc.data(), CRC_SIZE));
		uint32_t file_content_size = buff_file_content_size.value();
		crc = buff_crc.value();
	}
	catch (std::exception& e) 
	{
		std::cerr << "Exception: " << e.what() << "\n";
	}
	if (_crc == crc) /*crc good.*/
	{ 
		std::cout << "crc of server equals to crc of client.\n";
		send_success_message(reply_id);
	} 
	else 
	{
		_trying_to_send_crc++;
		if (send_crc == SEND_CRC) /*fourth time - error*/
		{ 
			std::cout << "crc not equal in the last time. exit.\n";
			send_abort_message(reply_id);
		} 
		else /*trying to send 3 times*/
		{ 
			std::cout << "crc not equal. try again.\n";
			send_not_success_message(reply_id);
			std::string enc = encrypt_file(_aes_key, _priv_key);
			send_encrypted_file_to_server(enc, reply_id);
		}
	}
}

/*this function gets answer from server about the crc*/
void get_answer(uint16_t answer_to) 
{
	uint8_t reply_id[ID_SIZE] = { '\0' };
	uint16_t code = get_header(); /*get header from server*/
	try 
	{
		size_t id_len = boost::asio::read(s, boost::asio::buffer(reply_id, ID_SIZE));
	} 
	catch (std::exception& e) 
	{
		std::cerr << "Exception: " << e.what() << "\n";
	}
	if (answer_to == VALID_CRC_REQUEST)
	{
		std::cout << "Server decrypted good well! Good Bye." << std::endl;
	}
	else
	{
		std::cout << "Server didn't succeed to decrypt well your file! Good Bye." << std::endl;
	}
}