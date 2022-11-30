#include <iostream>

#include <client_manager.h>

using namespace boost::asio; // delete me when io_service won't be created in main()

int main()
{
	udc::blob_t data;
	for (int i = 0 ; i < 1000 ; ++i)
	{
		data.push_back(i);
	}
	int t1 = 8005;
	io_service server; // delete me!
	udc::ClientManager test1(server , t1);
	test1.Connect();
	test1.GetKeys();
	//TODO: crypt
	test1.SendMessage(data);
	test1.CloseConnection();
	return 0;
}