#ifndef CLIENT_MANAGER_HEADER
#define CLIENT_MANAGER_HEADER

#include <boost/asio.hpp>
#include <boost/array.hpp>

#include "types.h"

namespace udc
{

using namespace boost::asio;

// TODO: docs?
class ClientManager
{
	ip::udp::socket m_udpSock;
	ip::tcp::socket m_tcpSock;

	int m_port;

	ip::udp::endpoint m_senderEndpoint;
	ip::tcp::endpoint m_serverEndpoint; 

	std::string ListenForBroadcast();    
public:
	ClientManager(io_service& server, int& p);
	
    void Connect();

    std::string GetCLInfo();

	udc::blob_t GetMessagge();
	
    void SendMessage(udc::blob_t& mess);
	
    void CloseConnection();
	
    ~ClientManager() {};
};

} // namespace udc

#endif // #define CLIENT_MANAGER_HEADER 
