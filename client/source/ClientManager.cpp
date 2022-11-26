#include <iostream>
#include <pthread.h>
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include "types.h"

using namespace boost::asio;

class ClientManager
{
public:
	void Connection();
	udc::blob_t GetKeys();
	void SendMess(udc::blob_t& mess);
	void CloseConnect();

	ClientManager(io_service& server, int& p);
	~ClientManager() {};

private:
	ip::udp::socket udp_sock;
	ip::tcp::socket tcp_sock;

	int port;

	ip::udp::endpoint sender_endpoint;
	ip::tcp::endpoint server_endpoint; 

	std::string listenForBroadcast();
};

ClientManager::ClientManager(io_service& server, int& p) : udp_sock(server, ip::udp::endpoint(ip::udp::v4(), 2222)),
                                                   tcp_sock(server), port(p)
{
	udp_sock.set_option(socket_base::broadcast(true));
}

std::string ClientManager::listenForBroadcast()
{
    std::string res;
    res.resize(15);

    std::size_t bytes_transferred = udp_sock.receive_from(boost::asio::buffer(res), sender_endpoint);

    std::cout << "got " << bytes_transferred << " bytes." << std::endl;
    for (auto&& it : res)
    {
        std::cout << it;
    }
    std::cout << std::endl;
    return res;
}

void ClientManager::Connection()
{
	std::string add = listenForBroadcast();
	server_endpoint = ip::tcp::endpoint(ip::address::from_string(add), port);

	try
    {
        tcp_sock.connect(server_endpoint);  
    }
    catch (boost::system::system_error& err)
    {
        std::cout << err.what() << std::endl;
    }
}

udc::blob_t ClientManager::GetKeys()
{
	/*
	 * Recieving Keys
	 */
    std::array<int, 1> key_size;
    tcp_sock.receive(boost::asio::buffer(key_size));

    udc::blob_t for_key;
    for_key.resize(key_size[0]);
    tcp_sock.receive(boost::asio::buffer(for_key));

    for (auto&& it : for_key)
    {
    	std::cout << "key: " << static_cast<unsigned>(it) << std::endl; 
    }

    std::cout << "KEY SIZE = " << key_size[0] << std::endl;

    return for_key;
}

void ClientManager::SendMess(udc::blob_t& mess)
{
	/*
     * Sending crypted data
     */
    for (auto&& it : mess)
    {
    	std::cout << "msg: " << static_cast<unsigned>(it) << std::endl; 
    }
    std::cout << "MESS SIZE = " << mess.size() << std::endl;

	std::array<int, 1> size_data;
	size_data[0] = mess.size();
 	tcp_sock.send(boost::asio::buffer(size_data));
	tcp_sock.send(boost::asio::buffer(mess));
}

void ClientManager::CloseConnect()
{
	tcp_sock.close();
}

int main()
{
	udc::blob_t data;
	for (int i = 0 ; i < 1000 ; ++i)
	{
		data.push_back(i);
	}
	int t1 = 8009;
	io_service server;
	ClientManager test1(server , t1);
	test1.Connection();
	test1.GetKeys();
	//TODO: crypt
	test1.SendMess(data);
	test1.CloseConnect();
	return 0;
}
