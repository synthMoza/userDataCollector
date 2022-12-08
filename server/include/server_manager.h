#ifndef SERVER_MANAGER_HEADER
#define SERVER_MANAGER_HEADER

#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <vector>
#include <thread>
#include "types.h"
#include <RSA_cryptor.h>
#include <PGP_cryptor.h>
#include <AES128_cryptor.h>
#include <SHA256_hash.h>
#include <double_cryptor.h>
#include <hash_based_signature.h>

namespace udc
{

using namespace boost::asio;

class ServerManager
{

       using RSA_SHA256_SignatureTester = HashBasedSignaturTester<SHA256_Hash, RSA_Decryptor>;
       using RSA_AES128_Decryptor = DoubleDecryptor<AES128_Cryptor, RSA_Decryptor>;
       using RSA_AES128_PGP_Decryptor = PGP_Decryptor<RSA_SHA256_SignatureTester, RSA_AES128_Decryptor>;

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

       std::vector<RSA_Key> m_publicKeys;
       std::vector<RSA_Key> m_privateKeys;
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
 