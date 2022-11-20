#include <AES128_cryptor.h>

using namespace udc;

static constexpr size_t AES_256_KEY_SIZE = 32;
static constexpr size_t AES_BLOCKSIZE    = 16;
static constexpr size_t BUFSIZE          = 1024;

void AES128_KeyGenerator::Generate()
{
    blob_t new_key(AES_256_KEY_SIZE + AES_BLOCKSIZE);

    if (!RAND_bytes(&new_key[0], AES_256_KEY_SIZE) || !RAND_bytes(&new_key[AES_256_KEY_SIZE], AES_BLOCKSIZE)) 
        throw std::runtime_error("Error in generating key\n");
    
    m_key.SetKey(new_key);
}

AES128_Cryptor::AES128_Cryptor() :
    m_ctx (std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_reset)>(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_reset)),
    m_params {
        .encrypt = 0,
        .cipherType = EVP_aes_256_cbc(),
    }
{
    if (!m_ctx || !m_params.cipherType) 
    {
        std::stringstream stream;
        stream << __PRETTY_FUNCTION__ << ":" << __LINE__ << "; " << ERR_error_string(ERR_get_error(), NULL);
        throw std::runtime_error(stream.str());
    }
}

blob_t AES128_Cryptor::Encrypt(const blob_t& inputBlob, const AES128_Key& key)
{
    auto encryptionKey = key.GetKeyForEncryption();
    if (encryptionKey.size() < AES_256_KEY_SIZE + AES_BLOCKSIZE)
        throw std::length_error("Key is too small");

    const unsigned char* opensslKey = &(encryptionKey[0]);
    const unsigned char* opensslIV = &(encryptionKey[AES_256_KEY_SIZE]);

    m_params.encrypt = 1;
    return Crypt(inputBlob, opensslKey, opensslIV);
}

blob_t AES128_Cryptor::Decrypt(const blob_t& inputBlob, const AES128_Key& key)
{
    auto decryptionKey = key.GetKeyForDecryption();
    if (decryptionKey.size() < AES_256_KEY_SIZE + AES_BLOCKSIZE)
        throw std::length_error("Key is too small");

    const unsigned char* opensslKey = &(decryptionKey[0]);
    const unsigned char* opensslIV = &(decryptionKey[AES_256_KEY_SIZE]);

    m_params.encrypt = 0;
    return Crypt(inputBlob, opensslKey, opensslIV);
}

blob_t AES128_Cryptor::Crypt(const blob_t& inputBlob, const unsigned char* opensslKey, const unsigned char* opensslIV)
{
    /* Allow enough space in output buffer for additional block */
    auto cipherBlockSize = EVP_CIPHER_block_size(m_params.cipherType);

    blob_t outBlob;
    outBlob.resize((inputBlob.size() / BUFSIZE + 1) * (BUFSIZE + static_cast<size_t>(cipherBlockSize)));

    /* Don't set key or IV right away; we want to check lengths */
    if (!EVP_CipherInit_ex(m_ctx.get(), m_params.cipherType, NULL, NULL, NULL, m_params.encrypt))
    {
        std::stringstream stream;
        stream << __PRETTY_FUNCTION__ << ":" << __LINE__ << "; " << ERR_error_string(ERR_get_error(), NULL);
        throw std::runtime_error(stream.str());
    }

    OPENSSL_assert(EVP_CIPHER_CTX_key_length(m_ctx.get()) == AES_256_KEY_SIZE);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(m_ctx.get()) == AES_BLOCK_SIZE);

    /* Now we can set key and IV */
    if (!EVP_CipherInit_ex(m_ctx.get(), nullptr, nullptr, opensslKey, opensslIV, m_params.encrypt))
    {
        std::stringstream stream;
        stream << __PRETTY_FUNCTION__ << ":" << __LINE__ << "; " << ERR_error_string(ERR_get_error(), NULL);
        throw std::runtime_error(stream.str());
    }

    size_t bytesRead = 0;
    size_t bytesWritten = 0;
    size_t bytesReadThisStep = 0;
    int outLength = 0;

    while(true) 
    {
        // Read in data in blocks until EOF. Update the ciphering with each read.
        bytesReadThisStep = inputBlob.size() >= BUFSIZE + bytesRead ? BUFSIZE : inputBlob.size() - bytesRead;

        if(!EVP_CipherUpdate(m_ctx.get(), &outBlob[bytesWritten], &outLength, &inputBlob[bytesRead], bytesReadThisStep))
        {
            std::stringstream stream;
            stream << __PRETTY_FUNCTION__ << ":" << __LINE__ << "; " << ERR_error_string(ERR_get_error(), NULL);
            throw std::runtime_error(stream.str());
        }
        
        bytesWritten += outLength;
        bytesRead += bytesReadThisStep;

        if (bytesReadThisStep < BUFSIZE)
            break;
    }

    /* Now cipher the final block and write it out to file */
    if (!EVP_CipherFinal_ex(m_ctx.get(), &outBlob[bytesWritten], &outLength)) 
    {
        std::stringstream stream;
        stream << __PRETTY_FUNCTION__ << ":" << __LINE__ << "; " << ERR_error_string(ERR_get_error(), NULL);
        throw std::runtime_error(stream.str());
    }

    bytesWritten += outLength;

    outBlob.resize(bytesWritten);
    outBlob.shrink_to_fit();

    return outBlob;
}
