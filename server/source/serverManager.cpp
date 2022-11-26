#include <iostream>
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include "types.h"

using namespace boost::asio;

class ServerManager
{
public:
       ServerManager(io_service& serv);
       void Connecting();
       void Broadcasting();
       udc::blob_t GetRecData()  { return RecData; }

       ~ServerManager() {};
private:
       ip::udp::socket udp_sock;            /*Socket for broadcast messaging*/
       ip::tcp::acceptor acc;               /*Acceptor for tcp connection*/
       ip::udp::endpoint endpointBroadcast; 
       udc::blob_t RecData;

       std::string GetOwnAddress();
       udc::blob_t Messaging(ip::tcp::socket& sock);
       void SendingBroadcast();
       void Connection();
       void MessProc();
};

ServerManager::ServerManager(io_service& serv) : udp_sock(serv, ip::udp::endpoint(ip::udp::v4(), 0)), 
                                                 acc(serv, ip::tcp::endpoint(ip::tcp::v4(), 8001)),
                                                 endpointBroadcast(ip::address_v4::broadcast(), 2222)
{
       udp_sock.set_option(socket_base::broadcast(true));
}


std::string ServerManager::GetOwnAddress()
{
       boost::asio::io_service server;
       std::string name = boost::asio::ip::host_name();
       ip::tcp::resolver res(server);
       ip::tcp::resolver::iterator it = res.resolve(ip::tcp::resolver::query(name, ""));

       std::string address = it->endpoint().address().to_string();

       return address;
}

udc::blob_t ServerManager::Messaging(ip::tcp::socket& sock)
{
       /*
        * Sending keys for crypting
        */
       udc::blob_t keys = {1 , 2 , 3 , 4 , 5};

       std::array<int, 1> sizes_send;
       sizes_send[0] = keys.size();

       sock.send(boost::asio::buffer(sizes_send));
       sock.send(boost::asio::buffer(keys));

       /*
        * Rececieving size of data
        */
       std::array<int, 1> sizes;
       sock.receive(boost::asio::buffer(sizes));
       std::cout << "SIZE = " << sizes[0] << std::endl;

       //Receieving data
       udc::blob_t for_msg;
       for_msg.resize(sizes[0]);
       sock.receive(boost::asio::buffer(for_msg));

       return for_msg;
}

void ServerManager::Connection()
{
       io_service serv;
       Broadcasting();
       acc = ip::tcp::acceptor(serv, ip::tcp::endpoint(ip::address::from_string(GetOwnAddress()), 8009));
       std::cout << GetOwnAddress() << std::endl;

       while (true)
       {
              ip::tcp::socket sock(serv);
              try
              {
                     acc.accept(sock);
                     std::cout << "CLIENT CONNECTED" << std::endl;
              }
              catch (boost::system::system_error& err)
              {
                     std::cout << err.what() << std::endl;
              }
              RecData = Messaging(sock);        
              MessProc();
              sock.close();

       }
}

void ServerManager::MessProc()
{

       //TODO:Encrypt data
       for (auto&& it : RecData)
       {
              std::cout << "msg = " << static_cast<unsigned>(it) << std::endl;
       }
}


void ServerManager::Connecting()
{
       std::thread broad(&ServerManager::Connection, this);
       broad.join();
}

void ServerManager::SendingBroadcast()
{
       std::string add = GetOwnAddress();
       while (true)
       {
              udp_sock.send_to(boost::asio::buffer(add), endpointBroadcast);
       }
}

void ServerManager::Broadcasting()
{
       std::thread broad(&ServerManager::SendingBroadcast, this);
       broad.detach();
}

int main()
{
       io_service server;
       ServerManager test(server);
       test.Broadcasting();
       test.Connecting();
       return 0;
}