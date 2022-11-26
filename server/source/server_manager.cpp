#include <server_manager.h>

#include <iostream>

using namespace udc;

ServerManager::ServerManager(io_service& serv) : 
       m_udpSock(serv, ip::udp::endpoint(ip::udp::v4(), 0)), 
       m_acc(serv, ip::tcp::endpoint(ip::tcp::v4(), 8001)),
       m_endpointBroadcast(ip::address_v4::broadcast(), 2222)
{
       m_udpSock.set_option(socket_base::broadcast(true));
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

void ServerManager::Connect()
{
       io_service serv;
       Broadcast();
       m_acc = ip::tcp::acceptor(serv, ip::tcp::endpoint(ip::address::from_string(GetOwnAddress()), 8009));
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
       std::string add = GetOwnAddress();
       while (true)
       {
              m_udpSock.send_to(boost::asio::buffer(add), m_endpointBroadcast);
       }
}

void ServerManager::Broadcast()
{
       std::thread broad(&ServerManager::SendingBroadcast, this);
       broad.detach();
}
