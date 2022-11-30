#include <client_manager.h>

#include <iostream>
#include <pthread.h>

using namespace udc;

ClientManager::ClientManager(io_service& server, int& p) : 
	m_udpSock(server, ip::udp::endpoint(ip::udp::v4(), p)),
	m_tcpSock(server), 
	m_port(p)
{
	m_udpSock.set_option(socket_base::broadcast(true));
}

std::string ClientManager::ListenForBroadcast()
{
    std::string res;
    res.resize(15);

    std::size_t bytes_transferred = m_udpSock.receive_from(boost::asio::buffer(res), m_senderEndpoint);

    std::cout << "got " << bytes_transferred << " bytes." << std::endl;
    for (auto&& it : res)
    {
        std::cout << it;
    }
    std::cout << std::endl;
    return res;
}

void ClientManager::Connect()
{
	std::string add = ListenForBroadcast();
	m_serverEndpoint = ip::tcp::endpoint(ip::address::from_string(add), m_port);

	try
    {
        m_tcpSock.connect(m_serverEndpoint);  
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
    m_tcpSock.receive(boost::asio::buffer(key_size));

    udc::blob_t for_key;
    for_key.resize(key_size[0]);
    m_tcpSock.receive(boost::asio::buffer(for_key));

    for (auto&& it : for_key)
    {
    	std::cout << "key: " << static_cast<unsigned>(it) << std::endl; 
    }

    std::cout << "KEY SIZE = " << key_size[0] << std::endl;

    return for_key;
}

void ClientManager::SendMessage(udc::blob_t& mess)
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
 	m_tcpSock.send(boost::asio::buffer(size_data));
	m_tcpSock.send(boost::asio::buffer(mess));
}

void ClientManager::CloseConnection()
{
	m_tcpSock.close();
}
