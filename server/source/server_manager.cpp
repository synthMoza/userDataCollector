#include <server_manager.h>

#include <iostream>
#include <chrono>
#include <thread>

using namespace udc;

ServerManager::ServerManager(io_service& serv, int& port) : 
       m_udpSock(serv, ip::udp::endpoint(ip::udp::v4(), 0)), 
       m_acc(serv, ip::tcp::endpoint(ip::tcp::v4(), 3333)),
       m_endpointBroadcast(ip::address_v4::broadcast(), port),
       m_port(port)
{
       m_udpSock.set_option(socket_base::broadcast(true));
}


std::string ServerManager::GetOwnAddress()
{
       boost::asio::io_service netService;
       ip::udp::resolver   resolver(netService);
       ip::udp::resolver::query query(ip::udp::v4(), "google.com", "");
       ip::udp::resolver::iterator endpoints = resolver.resolve(query);
       ip::udp::endpoint ep = *endpoints;
       ip::udp::socket socket(netService);
       socket.connect(ep);
       boost::asio::ip::address addr = socket.local_endpoint().address();
       std::cout << "My IP according to google is: " << addr.to_string() << std::endl;

       return addr.to_string();
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

void ServerManager::Connect()
{
       io_service serv;
       Broadcast();
       m_acc = ip::tcp::acceptor(serv, ip::tcp::endpoint(ip::address::from_string(GetOwnAddress()), m_port));
       std::cout << GetOwnAddress() << std::endl;

       while (true)
       {
              ip::tcp::socket sock(serv);
              try
              {
                     m_acc.accept(sock);
                     std::cout << "CLIENT CONNECTED" << std::endl;
              }
              catch (boost::system::system_error& err)
              {
                     std::cout << err.what() << std::endl;
              }
              m_recData = Messaging(sock);        
              ProcessMessage();
              sock.close();

       }
}

void ServerManager::ProcessMessage()
{

       //TODO:Encrypt data
       for (auto&& it : m_recData)
       {
              std::cout << "msg = " << static_cast<unsigned>(it) << std::endl;
       }
}

void ServerManager::SendingBroadcast()
{
       using namespace std::chrono_literals;
       
       std::string add = GetOwnAddress();
       while (true)
       {
              std::this_thread::sleep_for(5s);
              std::cout << "SENDING BROADCAST" << std::endl;
              m_udpSock.send_to(boost::asio::buffer(add), m_endpointBroadcast);
       }
}

void ServerManager::Broadcast()
{
       std::thread broad(&ServerManager::SendingBroadcast, this);
       broad.detach();
}
