#include <AES128_cryptor.h>
#include <thread>
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

blob_t AES128_Cryptor::Encrypt(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, const AES128_Key& key)
{
    auto encryptionKey = key.GetKey();
    if (encryptionKey.size() < AES_256_KEY_SIZE + AES_BLOCKSIZE)
        throw std::length_error("Key is too small");

    const unsigned char* opensslKey = &(encryptionKey[0]);
    const unsigned char* opensslIV = &(encryptionKey[AES_256_KEY_SIZE]);

    m_params.encrypt = 1;
    return Crypt(inputBlobStart, inputBlobEnd, opensslKey, opensslIV, m_threads);
}

blob_t AES128_Cryptor::Decrypt(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, const AES128_Key& key)
{
    auto decryptionKey = key.GetKey();
    if (decryptionKey.size() < AES_256_KEY_SIZE + AES_BLOCKSIZE)
        throw std::length_error("Key is too small");

    const unsigned char* opensslKey = &(decryptionKey[0]);
    const unsigned char* opensslIV = &(decryptionKey[AES_256_KEY_SIZE]);

    m_params.encrypt = 0;
    return Crypt(inputBlobStart, inputBlobEnd, opensslKey, opensslIV, m_threads);
}

namespace detail
{
    void AES_Crypt_1thr(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, EVP_CIPHER_CTX* ctx, int cipherBlockSize, blob_t& outputBlob)
    {
        size_t bytesReadThisStep = 0;
        size_t inputBlobSize = inputBlobEnd - inputBlobStart;
        size_t bytesRead = 0;
        size_t bytesWritten = 0;
        int outLength = 0;
        outputBlob.resize((inputBlobSize / BUFSIZE + 1) * (BUFSIZE + static_cast<size_t>(cipherBlockSize)));
        while(true) 
        {
            // Read in data in blocks until EOF. Update the ciphering with each read.
            bytesReadThisStep = inputBlobSize >= BUFSIZE + bytesRead ? BUFSIZE : inputBlobSize - bytesRead;

            if(!EVP_CipherUpdate(ctx, &outputBlob[bytesWritten], &outLength,  &(*(inputBlobStart + bytesRead)), bytesReadThisStep))
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
        outputBlob.resize(bytesWritten);
        outputBlob.shrink_to_fit();
    }
}

blob_t AES128_Cryptor::Crypt(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, const unsigned char* opensslKey, const unsigned char* opensslIV, size_t thread_count)
{
    /* Allow enough space in output buffer for additional block */
    auto cipherBlockSize = EVP_CIPHER_block_size(m_params.cipherType);

    size_t inputBlobSize = inputBlobEnd - inputBlobStart;

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

    size_t bytesWritten = 0;
    int outLength = 0;

    int sizePerThread = inputBlobSize / thread_count;
    int blocksPerThread = sizePerThread / BUFSIZE + 1;

    std::vector<std::thread> threads;
    int messageSizeLeft = inputBlobSize;
    int currentPos = 0;
    std::vector<blob_t> blobPerThread(thread_count);
    for (size_t i = 0; i < thread_count; ++i)
    {
        int sizeForThisThread = std::min(messageSizeLeft, static_cast<int>(blocksPerThread * BUFSIZE));
        threads.push_back(std::thread(detail::AES_Crypt_1thr, inputBlobStart + currentPos, inputBlobStart + currentPos + sizeForThisThread, m_ctx.get(), cipherBlockSize, std::ref(blobPerThread[i])));
        messageSizeLeft -= sizeForThisThread;
        currentPos += sizeForThisThread;

        if (messageSizeLeft == 0)
            break;
    }

    blob_t outData;

    for (size_t i = 0; i < threads.size(); i++) {
        threads[i].join();
        if (!blobPerThread[i].empty())
            outData.insert(outData.end(), blobPerThread[i].begin(), blobPerThread[i].end());
    }
    bytesWritten = outData.size();
    outData.resize((inputBlobSize / BUFSIZE + 1) * (BUFSIZE + static_cast<size_t>(cipherBlockSize)));
    /* Now cipher the final block and write it out to file */
    if (!EVP_CipherFinal_ex(m_ctx.get(), &outData[bytesWritten], &outLength)) 
    {
        std::stringstream stream;
        stream << __PRETTY_FUNCTION__ << ":" << __LINE__ << "; " << ERR_error_string(ERR_get_error(), NULL);
        throw std::runtime_error(stream.str());
    }

    bytesWritten += outLength;

    outData.resize(bytesWritten);
    outData.shrink_to_fit();

    return outData;
}
