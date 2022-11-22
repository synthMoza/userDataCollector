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

class RSA_PublicKey final : public IPublicKey<blob_t>
{
    blob_t m_key;
public:
    void SetKey(const blob_t& new_key) 
    {
        m_key = new_key;
    }

    virtual blob_t GetKeyForEncryption() const override 
    {
        return m_key;
    }
};

class RSA_PrivateKey final : public IPrivateKey<blob_t>
{
    blob_t m_key;
public:
    void SetKey(const blob_t& new_key) 
    {
        m_key = new_key;
    }

    virtual blob_t GetKeyForDecryption() const override 
    {
        return m_key;
    }
};

class RSA_KeyGenerator final : public IKeyGenerator<RSA_PublicKey, RSA_PrivateKey>
{
    RSA_PublicKey m_publicKey;
    RSA_PrivateKey m_privateKey;
public:
    virtual void Generate() override;

    virtual RSA_PublicKey GetPublicKey() const override
    {
        return m_publicKey;
    }

    virtual RSA_PrivateKey GetPrivateKey() const override
    {
        return m_privateKey;
    }

};

namespace detail
{
class RSA_CryptoAlgorithm
{
    RSA* CreateRSA(const blob_t& key, bool decrypt);

public:

    blob_t DoRSA(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, const blob_t& key, bool decrypt = false);
};
}

class RSA_Encryptor final : public IEncryptor<RSA_PublicKey>, protected detail::RSA_CryptoAlgorithm
{
public:
    virtual blob_t Encrypt(const blob_t& inputBlob, const RSA_PublicKey& key) override;
    virtual blob_t Encrypt(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, const RSA_PublicKey& key) override;
};

class RSA_Decryptor final : public IDecryptor<RSA_PrivateKey>, protected detail::RSA_CryptoAlgorithm
{
public:
    virtual blob_t Decrypt(const blob_t& inputBlob, const RSA_PrivateKey& key) override;
    virtual blob_t Decrypt(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, const RSA_PrivateKey& key) override;
};

}

#endif // #define RSA_CRYPTOR_LIB_HEADER