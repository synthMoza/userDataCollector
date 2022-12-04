#ifndef RSA_CRYPTOR_LIB_HEADER
#define RSA_CRYPTOR_LIB_HEADER

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <exception>
#include <stdexcept>
#include <sstream>
#include <memory>

#include "cryptor.h"

namespace udc
{

class RSA_Key final : public IKey<blob_t>
{
    blob_t m_key;
public:
    void SetKey(const blob_t& new_key) 
    {
        m_key = new_key;
    }

    virtual blob_t GetKey() const override 
    {
        return m_key;
    }
};

class RSA_KeyGenerator final : public IKeyGenerator<RSA_Key>
{
    RSA_Key m_publicKey;
    RSA_Key m_privateKey;
public:
    virtual void Generate() override;

    virtual RSA_Key GetPublicKey() const override
    {
        return m_publicKey;
    }

    virtual RSA_Key GetPrivateKey() const override
    {
        return m_privateKey;
    }

};

namespace detail
{
void DoRSA_1thr(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, const RSA* rsa, blob_t& outputBlob, bool decrypt);

class RSA_CryptoAlgorithm
{
    RSA* CreateRSA(const blob_t& key, bool decrypt);

public:

    blob_t DoRSA(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, const blob_t& key, bool decrypt = false, size_t thread_count = 1);
};
}

class RSA_Encryptor final : public IEncryptor<RSA_Key>, protected detail::RSA_CryptoAlgorithm
{
    size_t m_threads = 1;
public:
    virtual blob_t Encrypt(const blob_t& inputBlob, const RSA_Key& key) { return Encrypt(inputBlob.begin(), inputBlob.end(), key); }
    virtual blob_t Encrypt(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, const RSA_Key& key) override;

    void SetThreadsCount(size_t threads) { m_threads = threads; }
};

class RSA_Decryptor final : public IDecryptor<RSA_Key>, protected detail::RSA_CryptoAlgorithm
{
    size_t m_threads = 1;
public:
    virtual blob_t Decrypt(const blob_t& inputBlob, const RSA_Key& key) { return Decrypt(inputBlob.begin(), inputBlob.end(), key); }
    virtual blob_t Decrypt(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, const RSA_Key& key) override;

    void SetThreadsCount(size_t threads) { m_threads = threads; }
};

}

#endif // #define RSA_CRYPTOR_LIB_HEADER