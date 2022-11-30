#include <server_manager.h>

using namespace udc;

int main()
{
       io_service serv;
       int port = 8005;
       ServerManager test(serv, port);
       test.Broadcast();
       test.Connect();
       return 0;
}
