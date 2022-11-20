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

class AES128_Key : public IKey<blob_t, blob_t>, public IData
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
    virtual blob_t GetKeyForTestingSignature() const override 
    {
        return m_key;
    }
    virtual blob_t GetKeyForDecryption() const override 
    {
        return m_key;
    }
    virtual blob_t GetKeyForMakingSignature() const override 
    {
        return m_key;
    }

    virtual blob_t Serialize() override
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

class AES128_Cryptor : public ICryptor<AES128_Key, AES128_Key>
{
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_reset)> m_ctx;
    
    struct CipherParams 
    {
        unsigned encrypt;
        const EVP_CIPHER* cipherType;
    } m_params;

    blob_t Crypt(const blob_t& inputBlob, const unsigned char* openssl_key, const unsigned char* openssl_iv);
public:

    AES128_Cryptor();

    virtual blob_t Encrypt(const blob_t& inputBlob, const AES128_Key& key) override;

    virtual blob_t Decrypt(const blob_t& inputBlob, const AES128_Key& key) override;

    virtual bool TestSignature(const blob_t& inputBlob, const AES128_Key& key) 
    {
        static_cast<void>(key); // unused parameters
        static_cast<void>(inputBlob);
        
        return true; 
    }

    virtual blob_t MakeSignature(const blob_t& inputBlob, const AES128_Key& key) override
    {
        static_cast<void>(key); // unused parameter
        return inputBlob;
    }
};

}

#endif // #define AES128_CRYPTOR_LIB_HEADER