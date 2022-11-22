#ifndef TYPES_LIB_HEADER
#define TYPES_LIB_HEADER

#include <vector>
#include <cstdint>

namespace udc
{

using byte_t = uint8_t;
using blob_t = std::vector<byte_t>;
using blob_iterator_t = blob_t::iterator;
using blob_const_iterator_t = blob_t::const_iterator;

}

#endif // #define TYPES_LIB_HEADER
