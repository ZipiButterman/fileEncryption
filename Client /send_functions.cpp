#include "send_functions.h"

/*this function send public key to server*/
std::string send_public_key(std::string public_key) 
{
	std::ifstream my_file;
	std::string name, private_key, priv_key, id_str;
	std::vector <uint8_t> send_mes;
	my_file.open("me.info");
	getline(my_file, name);
	getline(my_file, id_str);
	while (getline(my_file, priv_key)) 
	{
		private_key += priv_key;
	}
	_priv_key = private_key;
	std::string id_new = HexToBytes(id_str);
	for (int i = 0; i < ID_SIZE; i++) /*insert id to vector will be sent to server.*/
	{
		send_mes.push_back(id_new.data()[i]);
	}
	send_mes = push_header_to_vector(send_mes, SEND_PUB_KEY_REQUEST, NAME_SIZE + PUBLIC_KEY_SIZE);
	/*insert payload (name and public key) to vector will be sent to server.*/
	for (int i = 0; i < NAME_SIZE; i++) 
	{
		send_mes.push_back(_name_line[i]);
	}
	for (int i = 0; i < PUBLIC_KEY_SIZE; i++) 
	{
		send_mes.push_back(public_key[i]);
	}
	write_to_server(send_mes, ID_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE + NAME_SIZE + PUBLIC_KEY_SIZE); /*send vector to server*/
	my_file.close();
	return private_key;
}

/*this function send the encrypted file to server.*/
void send_encrypted_file_to_server(std::string encrypt, uint8_t* id_address) 
{
	std::vector <uint8_t> send_mes;
	uint8_t content[CONTENT_FILE_SIZE];
	boost::endian::store_little_u32(content, (uint32_t)encrypt.size());
	for (int i = 0; i < ID_SIZE; i++) /*insert id to vector will be sent to server.*/
	{
		send_mes.push_back(id_address[i]);
	}
	send_mes = push_header_to_vector(send_mes, SEND_FILE_REQUEST, encrypt.size() + FILE_NAME_SIZE + CONTENT_FILE_SIZE);
	/*insert payload (content file size, file name and encrypted content) to vector will be sent to server.*/
	for (int i = 0; i < CONTENT_FILE_SIZE; i++)
	{
		send_mes.push_back(content[i]);
	}
	for (int i = 0; i < FILE_NAME_SIZE; i++)
	{
		send_mes.push_back(_file_name[i]);
	}
	for (int i = 0; i < encrypt.size(); i++)
	{
		send_mes.push_back(encrypt[i]);
	}
	write_to_server(send_mes, ID_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE + CONTENT_FILE_SIZE + FILE_NAME_SIZE + encrypt.size()); /*send vector to server*/
	get_crc(0); /*get crc from server to compare. send 0 to sign that client still didn't try to send crc*/
}

/*this function send success message to server to sign crc are equals*/
void send_success_message(uint8_t* id_address) 
{
	std::vector <uint8_t> send_mes;
	for (int i = 0; i < ID_SIZE; i++) /*insert id to vector will be sent to server.*/
	{
		send_mes.push_back(id_address[i]);
	}
	send_mes = push_header_to_vector(send_mes, VALID_CRC_REQUEST, FILE_NAME_SIZE);
	for (int i = 0; i < FILE_NAME_SIZE; i++) /*insert payload (file name) to vector will be sent to server.*/
	{
		send_mes.push_back(_file_name[i]);
	}
	write_to_server(send_mes, ID_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE + FILE_NAME_SIZE); /*send vector to server*/
	get_answer(VALID_CRC_REQUEST); /*get answer from server*/
}

/*this function send not success message to server to sign crc are not equals*/
void send_not_success_message(uint8_t* id_address) 
{
	std::vector <uint8_t> send_mes;
	for (int i = 0; i < ID_SIZE; i++) /*insert id to vector will be sent to server.*/
	{
		send_mes.push_back(id_address[i]);
	}
	send_mes = push_header_to_vector(send_mes, INVALID_CRC_REQUEST, FILE_NAME_SIZE);
	for (int i = 0; i < FILE_NAME_SIZE; i++) /*insert payload (file name) to vector will be sent to server.*/
	{
		send_mes.push_back(_file_name[i]);
	}
	write_to_server(send_mes, ID_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE + FILE_NAME_SIZE); /*send vector to server*/
}

/*this function send not success message to server to sign crc are not equals*/
void send_abort_message(uint8_t* id_address) 
{
	std::vector <uint8_t> send_mes;
	for (int i = 0; i < ID_SIZE; i++) /*insert id to vector will be sent to server.*/
	{
		send_mes.push_back(id_address[i]);
	}
	send_mes = push_header_to_vector(send_mes, LAST_INVALID_CRC_REQUEST, FILE_NAME_SIZE);
	for (int i = 0; i < FILE_NAME_SIZE; i++) /*insert payload (file name) to vector will be sent to server.*/
	{
		send_mes.push_back(_file_name[i]);
	}
	write_to_server(send_mes, ID_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE + FILE_NAME_SIZE);
	get_answer(LAST_INVALID_CRC_REQUEST); /*get answer from server*/
}
