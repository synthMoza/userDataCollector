#include <SHA256_hash.h>

#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <openssl/evp.h>

#include <exception>
#include <stdexcept>
#include <sstream>
#include <memory>

using namespace udc;

SHA256_Hash::SHA256_Hash() :
    m_ctx(std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>(EVP_MD_CTX_new(), &EVP_MD_CTX_free))
{
    if (m_ctx.get() == nullptr)
        throw std::runtime_error("Can't create context for SHA256\n");

    if (!EVP_DigestInit_ex(m_ctx.get(), EVP_sha256(), NULL))
        throw std::runtime_error("Can't init context for SHA256\n");
}

blob_t SHA256_Hash::CalculateHash(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd)
{
    if (!EVP_DigestInit_ex(m_ctx.get(), EVP_sha256(), NULL))
        throw std::runtime_error("Can't init context for SHA256\n");

    if (!EVP_DigestUpdate(m_ctx.get(), &(*inputBlobStart), inputBlobEnd - inputBlobStart))
        throw std::runtime_error("Can't calculate SHA256\n");

    blob_t hash(EVP_MAX_MD_SIZE);
    unsigned int lengthOfHash = 0;

    if (!EVP_DigestFinal_ex(m_ctx.get(), &(hash)[0], &lengthOfHash))
        throw std::runtime_error("Can't finish SHA256\n");

    hash.resize(lengthOfHash);
    hash.shrink_to_fit();
    return hash;
}