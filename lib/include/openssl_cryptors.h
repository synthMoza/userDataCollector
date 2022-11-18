#ifndef OPENSSL_CRYPTORS_LIB_HEADER
#define OPENSSL_CRYPTORS_LIB_HEADER

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

#include "cryptor.h"

constexpr size_t AES_256_KEY_SIZE = 32;
constexpr size_t AES_BLOCKSIZE    = 16;
constexpr size_t BUFSIZE          = 1024;

namespace udc
{

class OpenSSL_AES128_Key : public IKey<blob_t, blob_t>
{
public:
    void SetKey(const blob_t& new_key) {
        m_key = new_key;
    }
    virtual blob_t GetKeyForEncryption() const override {
        return m_key;
    }
    virtual blob_t GetKeyForTestingSignature() const override {
        return m_key;
    }
    virtual blob_t GetKeyForDecryption() const override {
        return m_key;
    }
    virtual blob_t GetKeyForMakingSignature() const override {
        return m_key;
    }
private:
    blob_t m_key;
};

class OpenSSL_AES128_KeyGenerator : public IKeyGenerator<OpenSSL_AES128_Key, OpenSSL_AES128_Key>
{
public:
    virtual void Generate() override
    {
        blob_t new_key(AES_256_KEY_SIZE + AES_BLOCKSIZE);
        if (!RAND_bytes(&new_key[0], AES_256_KEY_SIZE) || !RAND_bytes(&new_key[AES_256_KEY_SIZE], AES_BLOCKSIZE)) {
            throw std::runtime_error("Error in generating key\n");
        }
        m_key.SetKey(new_key);
    }

    virtual OpenSSL_AES128_Key GetPublicKey() const override
    {
        return m_key;
    }

    virtual OpenSSL_AES128_Key GetPrivateKey() const override
    {
        return m_key;
    }

private:
    OpenSSL_AES128_Key m_key;
};

class OpenSSL_AES128_Cryptor : public ICryptor<blob_t, blob_t>
{
public:

    OpenSSL_AES128_Cryptor() 
    {
        ctx = EVP_CIPHER_CTX_new();
        if (ctx == NULL) {
            fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        }

        params.cipher_type = EVP_aes_256_cbc();
    }

    ~OpenSSL_AES128_Cryptor() 
    {
        EVP_CIPHER_CTX_cleanup(ctx);
    }

    virtual blob_t Encrypt(const blob_t& inputBlob, const IPublicKey<blob_t>& key) override
    {
        if (key.GetKeyForEncryption().size() < AES_256_KEY_SIZE + AES_BLOCK_SIZE)
            throw std::length_error("Key is too small");

        const unsigned char* openssl_key = &(key.GetKeyForEncryption()[0]);
        const unsigned char* openssl_iv = &(key.GetKeyForEncryption()[AES_256_KEY_SIZE]);

        params.encrypt = 1;
        return AES128Crypt(inputBlob, openssl_key, openssl_iv);
    }

    virtual blob_t Decrypt(const blob_t& inputBlob, const IPrivateKey<blob_t>& key) override
    {
        if (key.GetKeyForDecryption().size() < AES_256_KEY_SIZE + AES_BLOCKSIZE)
            throw std::length_error("Key is too small");

        const unsigned char* openssl_key = &(key.GetKeyForDecryption()[0]);
        const unsigned char* openssl_iv = &(key.GetKeyForDecryption()[AES_256_KEY_SIZE]);

        params.encrypt = 0;
        return AES128Crypt(inputBlob, openssl_key, openssl_iv);
    }

    virtual bool   TestSignature(const blob_t& inputBlob, const IPublicKey<blob_t>& key) 
    {
        static_cast<void>(key); // unused parameters
        static_cast<void>(inputBlob);
        
        return true; 
    }

    virtual blob_t MakeSignature(const blob_t& inputBlob, const IPrivateKey<blob_t>& key) override
    {
        static_cast<void>(key); // unused parameter
        return inputBlob;
    }

    protected:

    virtual blob_t AES128Crypt(const blob_t& inputBlob, const unsigned char* openssl_key, const unsigned char* openssl_iv)
    {
        /* Allow enough space in output buffer for additional block */
        int cipher_block_size = EVP_CIPHER_block_size(params.cipher_type);
        blob_t out_buf(BUFSIZE + cipher_block_size);
        blob_t outBlob;

        /* Don't set key or IV right away; we want to check lengths */
        if (!EVP_CipherInit_ex(ctx, params.cipher_type, NULL, NULL, NULL, params.encrypt)){
            throw std::runtime_error(ERR_error_string(ERR_get_error(), NULL));
        }

        OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == AES_256_KEY_SIZE);
        OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == AES_BLOCK_SIZE);

        /* Now we can set key and IV */
        if (!EVP_CipherInit_ex(ctx, NULL, NULL, openssl_key, openssl_iv, params.encrypt)){
            throw std::runtime_error(ERR_error_string(ERR_get_error(), NULL));
        }

        size_t num_bytes_read = 0;
        size_t num_bytes_read_this_step = 0;
        int out_len = 0;

        while(1) {
            // Read in data in blocks until EOF. Update the ciphering with each read.
            num_bytes_read_this_step = inputBlob.size() >= BUFSIZE + num_bytes_read ? BUFSIZE : inputBlob.size() - num_bytes_read;

            if(!EVP_CipherUpdate(ctx, &out_buf[0], &out_len, &inputBlob[num_bytes_read], num_bytes_read_this_step)){
                throw std::runtime_error(ERR_error_string(ERR_get_error(), NULL));
            }
            
            outBlob.insert(outBlob.end(), out_buf.begin(), out_buf.begin() + out_len);

            num_bytes_read += num_bytes_read_this_step;

            if (num_bytes_read_this_step < BUFSIZE) {
                break;
            }
        }

        /* Now cipher the final block and write it out to file */
        if(!EVP_CipherFinal_ex(ctx, &out_buf[0], &out_len)) {
            throw std::runtime_error(ERR_error_string(ERR_get_error(), NULL));
        }

        outBlob.insert(outBlob.end(), out_buf.begin(), out_buf.begin() + out_len);

        return outBlob;
    }


private:
    EVP_CIPHER_CTX* ctx;
    struct _cipher_params_t {
        unsigned int encrypt;
        const EVP_CIPHER *cipher_type;
    } params;

};

}

#endif // #define CRYPTOR_LIB_HEADER