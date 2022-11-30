#ifndef SHA256_HASH_LIB_HEADER
#define SHA256_HASH_LIB_HEADER
#include <openssl/evp.h>
#include "hash.h"
#include <exception>
#include <stdexcept>
#include <sstream>
#include <memory>
namespace udc
{

class SHA256_Hash : public IHash
{
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> m_ctx;
public:
    SHA256_Hash();

    virtual blob_t CalculateHash(const blob_t& inputBlob) override { return CalculateHash(inputBlob.begin(), inputBlob.end()); }
    virtual blob_t CalculateHash(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd) override;
};

}
#endif // #define SHA256_HASH_LIB_HEADER