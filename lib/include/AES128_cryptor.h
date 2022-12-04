#ifndef AES128_CRYPTOR_LIB_HEADER
#define AES128_CRYPTOR_LIB_HEADER

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#include <exception>
#include <stdexcept>
#include <sstream>
#include <memory>

#include "data.h"
#include "cryptor.h"

namespace udc
{

class AES128_Key : public IKey<blob_t>, public IData
{
    blob_t m_key;
public:
    void SetKey(const blob_t& new_key) override
    {
        m_key = new_key;
    }
    virtual blob_t GetKey() const override 
    {
        return m_key;
    }

    virtual blob_t Serialize() const override
    {
        return m_key;
    }

    virtual void Deserialize(const blob_t& blob) override
    {
        SetKey(blob);
    }
};

class AES128_KeyGenerator : public IKeyGenerator<AES128_Key, AES128_Key>
{
    AES128_Key m_key;
public:
    virtual void Generate() override;

    virtual AES128_Key GetPublicKey() const override
    {
        return m_key;
    }

    virtual AES128_Key GetPrivateKey() const override
    {
        return m_key;
    }

};

class AES128_Cryptor : public ICryptor<AES128_Key>
{
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_reset)> m_ctx;
    
    struct CipherParams 
    {
        unsigned encrypt;
        const EVP_CIPHER* cipherType;
    } m_params;
    size_t m_threads = 1;
    blob_t Crypt(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, const unsigned char* openssl_key, const unsigned char* openssl_iv, size_t thread_count);
public:

    AES128_Cryptor();

    virtual blob_t Encrypt(const blob_t& inputBlob, const AES128_Key& key) { return Encrypt(inputBlob.begin(), inputBlob.end(), key); }
    virtual blob_t Encrypt(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, const AES128_Key& key) override;

    virtual blob_t Decrypt(const blob_t& inputBlob, const AES128_Key& key) { return Decrypt(inputBlob.begin(), inputBlob.end(), key); }
    virtual blob_t Decrypt(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, const AES128_Key& key) override;

    void SetThreadsCount(size_t threads) { m_threads = threads; }
};

}

#endif // #define AES128_CRYPTOR_LIB_HEADER