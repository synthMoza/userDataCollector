#ifndef HASH_LIB_HEADER
#define HASH_LIB_HEADER

#include "types.h"

namespace udc
{

class IHash
{
public:

    virtual blob_t CalculateHash(const blob_t& inputBlob) = 0;
    virtual blob_t CalculateHash(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd) = 0;
};

}

#endif // #define HASH_LIB_HEADER