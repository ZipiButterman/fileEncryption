#include "client.h"

char _name_line[NAME_SIZE] = { '\0' };
char _file_name[FILE_NAME_SIZE] = { '\0' };
char _path_line[PATH_SIZE] = { '\0' };
std::string path;
std::string _aes_key;
std::string _priv_key;

int main(int argc, char* argv[]) 
{
	std::string public_key, private_key;
	connect_to_server(); /*connect to server (using ip and port from 'transfer.info' file*/
	int success = 0;
	std::ifstream check_me_file("me.info");
	if (check_me_file.good()) /*almost regised*/
	{ 
		private_key = read_priv_file();
		success = reconnect(private_key);
	}
	if (!check_me_file.good() || success == INVALID_RECONNECT_ANSWER) /*me file not exists. new client*/
	{ 
		public_key = regist(); /*regist from beginning*/
		private_key = send_public_key(public_key);
		get_encrypted_public_key(private_key);
	}
}

/*this function read data from 'transfer.info' file (including ip and port) and connect to server*/
void connect_to_server() 
{
	std::ifstream trans;
	std::string ip_port, ip, port, file_name, name;
	trans.open("transfer.info");
	if (trans.is_open()) /*succeed to open transfer file*/
	{ 
		getline(trans, ip_port);
		getline(trans, name);
		getline(trans, path);
		size_t pos_file_name = path.find_last_of('/');
		size_t pos = ip_port.find(':');
		ip = ip_port.substr(0, pos);
		port = ip_port.substr(pos + 1);
		if (pos_file_name == std::string::npos) /*path name is simply the file name*/
		{
			file_name = path;
		}
		else
		{
			file_name = path.substr(pos_file_name + 1);
		}
		strcpy_s(_name_line, name.data());
		strcpy_s(_file_name, file_name.data());
		for (int i = name.size(); i < NAME_SIZE; i++) /*padding _name_line to be size of 255 with character '\0'*/
		{
			_name_line[i] = '\0';
		}
		for (int i = file_name.size(); i < FILE_NAME_SIZE; i++) /*padding _file_name to be size of 255 with character '\0'*/
		{
			_file_name[i] = '\0';
		}
		trans.close();
	} 
	else 
	{
		std::cout << "not found 'transfer.info' file. exit.\n";
		exit(1);
	}
	boost::asio::connect(s, resolver.resolve(ip, port)); /*connect with ip and port*/
	std::cout << "connect to server.\n";
}

/*user registed already*/
int reconnect(std::string private_key) 
{
	std::ifstream my_file;
	std::string name_str, id_str;
	std::vector <uint8_t> send_mes;
	uint8_t reply_id[ID_SIZE];
	my_file.open("me.info"); /*me exists (checked in main function)*/
	getline(my_file, name_str);
	getline(my_file, id_str);
	my_file.close();
	strcpy_s(_name_line, name_str.data());
	for (int i = name_str.size(); i < NAME_SIZE; i++) /*padding _name_line to be size of 255 with character '\0'*/
	{
		_name_line[i] = '\0';
	}
	for (int i = 0; i < ID_SIZE; i++) /*insert id to the vector will be sent to server*/
	{
		send_mes.push_back(id_str[i]);
	}
	send_mes = push_header_to_vector(send_mes, RECONNECT_REQUEST, NAME_SIZE);
	for (int i = 0; i < NAME_SIZE; i++) /*insert payload (name) to the vector will be sent to server*/
	{
		send_mes.push_back(_name_line[i]);
	}
	write_to_server(send_mes, ID_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE + NAME_SIZE); /*send vector to server*/
	uint8_t* id_add = get_key_from_server(reply_id);
	if (id_add == NULL) /*server didn't find name, regist from beginning*/
	{
		std::cout << "server didn't find your name, try to regist from beginning.\n";
		return INVALID_RECONNECT_ANSWER;
	}
	std::string encrypt = encrypt_file(_aes_key, private_key);
	send_encrypted_file_to_server(encrypt, reply_id);
	return 0;
}

/*this function regists new user to the system*/
std::string regist() 
{
	uint8_t reply_id[ID_SIZE] = { '\0' };
	std::vector <uint8_t> send_mes;
	for (int i = 0; i < ID_SIZE; i++) /*user not exists - there is no uuid - send 0*/
	{
		send_mes.push_back('0');
	}
	send_mes = push_header_to_vector(send_mes, REGISTRATION_REQUEST, NAME_SIZE);
	for (int i = 0; i < NAME_SIZE; i++)  /*insert payload (name) to the vector will be sent to server*/
	{
		send_mes.push_back(_name_line[i]);
	}
	write_to_server(send_mes, ID_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE + NAME_SIZE); /*send vector to server*/
	uint16_t answer_code = get_header(); /*get header from server*/
	if (answer_code == REGISTRATION_SUCCEED_ANSWER) 
	{
		try 
		{
			size_t id_length = boost::asio::read(s, boost::asio::buffer(reply_id, ID_SIZE));
			std::cout << "Registration succeeded. uuid (in hex) is: " << toHexStr(reply_id, ID_SIZE) << std::endl;
		} 
		catch (std::exception& e) 
		{
			std::cerr << "Exception: " << e.what() << "\n";
		}
	} 
	else 
	{
		std::cout << "Registration failed. exit.\n";
		exit(1);
	}
	/*create keys*/
	RSAPrivateWrapper* priv_key = new RSAPrivateWrapper();
	const std::string private_key = priv_key->getPrivateKey();
	const std::string public_key = priv_key->getPublicKey();
	Base64Wrapper base64;
	create_me_file(base64, _name_line, private_key, reply_id);
	create_priv_file(base64, private_key);
	return public_key;
}

/*this function sends the data to the server*/
void write_to_server(std::vector <uint8_t> send_mes, int size) 
{
	try 
	{
		boost::asio::write(s, boost::asio::buffer(send_mes, size)); /*send vector to server*/
	} 
	catch (std::exception& e) 
	{
		std::cerr << "Exception: " << e.what() << "\n";
	}
}


