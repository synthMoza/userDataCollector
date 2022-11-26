#include <server_manager.h>

using namespace udc;

int main()
{
       io_service server;
       ServerManager test(server);
       test.Broadcast();
       test.Connect();
       return 0;
}
