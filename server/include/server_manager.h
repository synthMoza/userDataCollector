#ifndef SERVER_MANAGER_HEADER
#define SERVER_MANAGER_HEADER

#include <boost/asio.hpp>
#include <boost/array.hpp>
#include "types.h"

namespace udc
{

using namespace boost::asio;

class ServerManager
{
       ip::udp::socket m_udpSock;            /*Socket for broadcast messaging*/
       ip::tcp::acceptor m_acc;               /*acceptor for tcp connection*/
       ip::udp::endpoint m_endpointBroadcast; 
       udc::blob_t m_recData;

       std::string GetOwnAddress();
       udc::blob_t Messaging(ip::tcp::socket& sock);
       void SendingBroadcast();
       void ProcessMessage();
public:
       ServerManager(io_service& serv);
       
       void Connect();
       void Broadcast();
       udc::blob_t GetRecData()  { return m_recData; }

       ~ServerManager() {};
};

}

#endif // #define SERVER_MANAGER_HEADER
 