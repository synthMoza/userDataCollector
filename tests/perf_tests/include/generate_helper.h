#ifndef GENERATE_RANDOM_H
#define GENERATE_RANDOM_H

#include <random>
#include <algorithm>
#include <climits>

#include <types.h>

namespace udc
{

namespace helpers
{

using random_bytes_engine = std::independent_bits_engine<std::default_random_engine, CHAR_BIT, byte_t>;

blob_t GenerateRandomData(size_t size)
{
    random_bytes_engine engine;
    blob_t vector(size);
    
    std::generate(vector.begin(), vector.end(), std::ref(engine));
    return vector;
}

}

}

#endif // #define GENERATE_RANDOM_H
 