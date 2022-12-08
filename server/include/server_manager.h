#ifndef SERVER_MANAGER_HEADER
#define SERVER_MANAGER_HEADER

#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <vector>
#include <thread>
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
       void Messaging(int& n);
       void SendingBroadcast();
       void ProcessMessage();
       blob_t ReciveMessage(int& n);
       void SendMessage(int& n, blob_t& mess);

       int m_port;
       bool is_end;
       std::vector<ip::tcp::socket> sockets;
       std::vector<std::thread> clients;
public:
       ServerManager(io_service& serv , int& port);
       
       void Connect();
       void Broadcast();
       udc::blob_t GetRecData()  { return m_recData; }
       void close();

       ~ServerManager() {};
};

}

#endif // #define SERVER_MANAGER_HEADER
 