#ifndef CRYPTOR_LIB_HEADER
#define CRYPTOR_LIB_HEADER

namespace udc
{

/*
    TODO (eganian.aa@phystech.edu):
    
    Come up with a cryptors interface, take into consideration - 
    they have to be flexible enough, so maybe there might be a
    separate "key_generator.h" and KeyGenerator might be a template
    parameter. They have to have, as a part of their interface, something
    like this:
        blob_t Encrypt(blob_t& inputBlob);
        blob_t Decrypt(blob_t& inputBlob);

*/

class Encryptor
{};

class Decryptor
{};

}

#endif // #define CRYPTOR_LIB_HEADER
 