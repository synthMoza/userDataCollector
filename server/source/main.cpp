#include <iostream>

// ===========================

/*
    ONLY FOR EXAMPLE, REMOVE ME LATER
*/

#include <data.h>

using namespace udc;

class HardDriveData : public IData
{
public:
    blob_t Serialize() override 
    {
        return {};
    };

    void Deserialize(blob_t& blob) override
    {
        static_cast<void>(blob);
        
        return ;
    }
};

// ===========================

int main(int argc, char* argv[])
{
    // unused parameters
    static_cast<void>(argc);
    static_cast<void>(argv);

    /*
        TODO (eganian.aa@phystech.edu):

        * Server interface might display his address with port, or share it via local network (as this server is a study project)
        * Server might have to log his connections and use fork()/pthread_create() for different connections
    */

    return EXIT_SUCCESS;
}
