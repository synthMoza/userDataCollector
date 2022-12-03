#include <client_manager.h>

#include <fstream>
#include <iostream>
#include <pthread.h>
#include "log.h"

#define CL_HPP_TARGET_OPENCL_VERSION 200
#include <CL/cl2.hpp>

using namespace udc;
using namespace mlog;

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

    m_udpSock.receive_from(boost::asio::buffer(res), m_senderEndpoint);

    PrintDataInfo("Get broadcasted address: ");

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

    PrintDataInfo("Key recieved: ");
    std::cout << std::endl << "Key size = " << key_size[0] << std::endl;

    for (auto&& it : for_key)
    {
    	std::cout << static_cast<unsigned>(it); 
    }
    std::cout << std::endl;

    return for_key;
}

void ClientManager::SendMessage(udc::blob_t& mess)
{
	/*
     * Sending crypted data
     */

    PrintDataInfo("Sending message: ");
    std::cout << std::endl;

    for (auto&& it : mess)
    {
    	std::cout << (it); 
    }
    std::cout << std::endl  << "Message size = " << mess.size() << std::endl;

	std::array<int, 1> size_data;
	size_data[0] = mess.size();
 	m_tcpSock.send(boost::asio::buffer(size_data));
	m_tcpSock.send(boost::asio::buffer(mess));
}

void ClientManager::CloseConnection()
{
	m_tcpSock.close();
}

std::string ClientManager::GetCLInfo()
{
    std::vector<cl::Platform> platforms;
    cl::Platform::get(&platforms);

    std::stringstream fout;

    fout << "Number of platforms: " << platforms.size() << std::endl << std::endl;

    for (const auto& platform : platforms)
    {
        std::vector<cl::Device> devices;
        platform.getDevices(CL_DEVICE_TYPE_ALL , &devices);

        fout << "Platform name: " << platform.getInfo<CL_PLATFORM_NAME>() << std::endl;
        fout << "Platform extensions: " << platform.getInfo<CL_PLATFORM_EXTENSIONS>() << std::endl;
        fout << "Platform profile: " << platform.getInfo<CL_PLATFORM_PROFILE>() << std::endl;
        fout << "Platform vendor: " << platform.getInfo<CL_PLATFORM_VENDOR>() << std::endl << std::endl;
        fout << "Platform version: " << platform.getInfo<CL_PLATFORM_VERSION >() << std::endl << std::endl;

        fout << "Number of devices: " << devices.size() << std::endl;
        
        for (const auto& device : devices)
        {   
            fout << "Device name: " << device.getInfo<CL_DEVICE_NAME>() << std::endl;

            fout << "Device build in kernels: " << device.getInfo<CL_DEVICE_BUILT_IN_KERNELS>() << std::endl;
            fout << "Device extensions: " << device.getInfo<CL_DEVICE_EXTENSIONS >() << std::endl;
            fout << "Device profile: " << device.getInfo<CL_DEVICE_PROFILE>() << std::endl;
            fout << "Device vendor: " << device.getInfo<CL_DEVICE_VENDOR>() << std::endl;
            fout << "Device version: " << device.getInfo<CL_DEVICE_VERSION>() << std::endl;
            fout << "Driver version: " << device.getInfo<CL_DRIVER_VERSION>() << std::endl;

            fout << "Version: " << device.getInfo<CL_DEVICE_OPENCL_C_VERSION>() << std::endl;
            fout << "Type: " << device.getInfo<CL_DEVICE_TYPE>() << std::endl;
            fout << " (GPU type number = " << CL_DEVICE_TYPE_GPU << ")" << std::endl;
            fout << "Available: " << device.getInfo<CL_DEVICE_AVAILABLE>() << std::endl;
            fout << "Address size: " << device.getInfo<CL_DEVICE_ADDRESS_BITS>() << std::endl;
            fout << "Little-endian: " << device.getInfo<CL_DEVICE_ENDIAN_LITTLE>() << std::endl;
            fout << "Global memory cache size: " << device.getInfo<CL_DEVICE_GLOBAL_MEM_CACHE_SIZE>() << std::endl;
            fout << "Global memory cache type: " << device.getInfo<CL_DEVICE_GLOBAL_MEM_CACHE_TYPE>();
            fout << " (read-write cache type = " << CL_READ_WRITE_CACHE << ")" << std::endl;
            fout << "Image support: " << device.getInfo<CL_DEVICE_IMAGE_SUPPORT>() << std::endl;
            fout << "Local memory size: " << device.getInfo<CL_DEVICE_LOCAL_MEM_SIZE>() << std::endl;
            fout << "Maximal frequency: " << device.getInfo<CL_DEVICE_MAX_CLOCK_FREQUENCY>() << std::endl;
        }
    }

    return fout.str();
}
