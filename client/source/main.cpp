#include <iostream>

// ===========================

/*
    ONLY FOR EXAMPLE, REMOVE ME LATER
*/

#include <data.h>

using namespace udc;

class LogData : public IData
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

        * Client interface might include input from user for server address to use.
        * Does client need some other "things" besides just connecting to the server?
    */

    return EXIT_SUCCESS;
}