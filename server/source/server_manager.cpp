#include <server_manager.h>

#include <iostream>
#include <chrono>
#include <thread>
#include "log.h"

using namespace udc;
using namespace mlog;

ServerManager::ServerManager(io_service& serv, int& port) : 
       m_udpSock(serv, ip::udp::endpoint(ip::udp::v4(), 0)), 
       m_acc(serv, ip::tcp::endpoint(ip::tcp::v4(), 3333)),
       m_endpointBroadcast(ip::address_v4::broadcast(), port),
       m_port(port),
       is_end(false)
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

       return addr.to_string();
}

void ServerManager::Messaging(int& n)
{
       /*Here you should write some memore(sending or recieving message)*/
       blob_t data = {1 , 2 , 3 , 4 , 5};
       SendMessage(n, data);
       data = ReciveMessage(n);
       for (auto&& it : data)
       {
              std::cout << it;
       }
       sockets[n].close();
}

void ServerManager::SendMessage(int& n, blob_t& mess)
{

       std::array<int, 1> sizes_send;
       sizes_send[0] = mess.size();

       sockets[n].send(boost::asio::buffer(sizes_send));
       sockets[n].send(boost::asio::buffer(mess));
}

blob_t ServerManager::ReciveMessage(int& n)
{
       std::array<int, 1> sizes;
       sockets[n].receive(boost::asio::buffer(sizes));
       PrintDataInfo("Got message");
       std::cout << std::endl << "Message's size = " << sizes[0] << std::endl;

       //Receieving data
       blob_t for_msg;
       for_msg.resize(sizes[0]);
       sockets[n].receive(boost::asio::buffer(for_msg));

       return for_msg;
}

void ServerManager::close()
{
       is_end = true;
}

void ServerManager::Connect()
{
       io_service serv;
       std::string addr = GetOwnAddress();
       std::string forPrint("My IP: " );
       forPrint = forPrint + addr;
       PrintDataInfo(forPrint);
       std::cout << std::endl;
       m_acc = ip::tcp::acceptor(serv, ip::tcp::endpoint(ip::address::from_string(addr), m_port));

       while (true)
       {
              boost::system::error_code ec;
              m_acc.listen(socket_base::max_connections, ec);
              try
              {
                     ip::tcp::socket m_tcpSock(serv);
                     sockets.emplace_back(serv);
                     m_acc.accept(sockets.back());
                     PrintDataInfo("Client connected");
                     int n = sockets.size() - 1;
                     clients.push_back(std::thread(&ServerManager::Messaging, this, std::ref(n)));
                     std::cout << std::endl;
              }
              catch (boost::system::system_error& err)
              {
                     std::cout << err.what() << std::endl;
              }   
              if (is_end)
              {
                     break;
              }     
       }
       for (auto&& it : clients)
       {
              it.join();
       }
}

void ServerManager::ProcessMessage()
{

       //TODO:Encrypt data
       for (auto&& it : m_recData)
       {
              std::cout << (it);
       }
}

void ServerManager::SendingBroadcast()
{
       using namespace std::chrono_literals;
       
       std::string add = GetOwnAddress();
       while (true)
       {
              std::this_thread::sleep_for(5s);

              PrintDataInfo("Sending broadcast");
              std::cout << std::endl;
              m_udpSock.send_to(boost::asio::buffer(add), m_endpointBroadcast);
       }
}

void ServerManager::Broadcast()
{
       std::thread broad(&ServerManager::SendingBroadcast, this);
       broad.detach();
}
