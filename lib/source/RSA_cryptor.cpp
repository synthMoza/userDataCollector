#include <RSA_cryptor.h>
#include <iostream>
#include <thread>

using namespace udc;

using BN_ptr = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;
using RSA_ptr = std::unique_ptr<RSA, decltype(&::RSA_free)>;
using EVP_KEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using BIO_FILE_ptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;

void RSA_KeyGenerator::Generate()
{
    RSA_ptr rsa(RSA_new(), ::RSA_free);
    BN_ptr bn(BN_new(), ::BN_free);
    BN_set_word(bn.get(), RSA_F4); // generating big number for key
    RSA_generate_key_ex(rsa.get(), 2048, bn.get(), nullptr); // generating key

    BIO_FILE_ptr bio(BIO_new(BIO_s_mem()), ::BIO_free); // IO for exporting key to C-string
    PEM_write_bio_RSAPrivateKey(bio.get(), rsa.get(), nullptr, nullptr, 0, nullptr, nullptr); // write private key to BIO
    blob_t privateKey;
    int keylen = BIO_pending(bio.get());
    privateKey.resize(keylen);
    BIO_read(bio.get(), &privateKey[0], keylen); // read private key from BIO to C-string

    PEM_write_bio_RSAPublicKey(bio.get(), rsa.get()); // same for public key
    blob_t publicKey;
    keylen = BIO_pending(bio.get());
    publicKey.resize(keylen);
    BIO_read(bio.get(), &publicKey[0], keylen);

    m_privateKey.SetKey(privateKey);
    m_publicKey.SetKey(publicKey);
}


RSA* detail::RSA_CryptoAlgorithm::CreateRSA(const blob_t& key, bool decrypt)
{
    RSA *rsa = nullptr;
    BIO *keybio;
    keybio = BIO_new_mem_buf(&key[0], -1); // creating BIO with key
    if (keybio == nullptr) 
        throw std::runtime_error("Can't create BIO\n");
    
    if (!decrypt) // create RSA instance with this key
        rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, nullptr, nullptr);
    else 
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, nullptr, nullptr);

    if (rsa == nullptr)
        throw std::runtime_error("Can't create RSA\n");

    return rsa;
}

void detail::DoRSA_1thr(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, const RSA* rsa, blob_t& outputBlob, bool decrypt)
{
    size_t blockSize; 
    size_t inputBlobSize = inputBlobEnd - inputBlobStart;

    if (decrypt)
    { // while using RSA_PKCS1_OAEP_PADDING, block size should be RSA_size(rsa) for decryption
        blockSize = RSA_size(rsa);
        outputBlob.resize((blockSize) * (inputBlobSize / (blockSize) + 1));
    }
    else
    { // and RSA_size(rsa) - 42 for encryption
        blockSize = RSA_size(rsa) - 42;
        outputBlob.resize((blockSize + 42) * (inputBlobSize / (blockSize) + 1));
    }

    size_t currentOutDataSize = 0;

    for (size_t blockStart = 0; blockStart < inputBlobSize; blockStart += blockSize) // cryption with block
    {
        int processingLen = blockStart + blockSize < inputBlobSize ? blockSize : inputBlobSize - blockStart;
        int writtenSize = 0;
        if (!decrypt) 
        {
            writtenSize = RSA_public_encrypt(processingLen, &(*(inputBlobStart + blockStart)), &outputBlob[currentOutDataSize], const_cast<RSA*>(rsa), RSA_PKCS1_OAEP_PADDING);
            if (writtenSize == -1)
                throw std::runtime_error("Unable to encrypt\n");
        }
        else 
        {
            writtenSize = RSA_private_decrypt(processingLen, &(*(inputBlobStart + blockStart)), &outputBlob[currentOutDataSize], const_cast<RSA*>(rsa), RSA_PKCS1_OAEP_PADDING);
            if (writtenSize == -1)
                throw std::runtime_error("Unable to decrypt\n");
        }
        currentOutDataSize += writtenSize;
    }
    outputBlob.resize(currentOutDataSize);
}

blob_t detail::RSA_CryptoAlgorithm::DoRSA(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, const blob_t& key, bool decrypt)
{
    RSA * rsa = CreateRSA(key, decrypt);

    blob_t outData;
    DoRSA_1thr(inputBlobStart, inputBlobEnd, rsa, std::ref(outData), decrypt);
    return outData;
}

blob_t RSA_Encryptor::Encrypt(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, const RSA_Key& key)
{
    blob_t blob_key = key.GetKey();

    return DoRSA(inputBlobStart, inputBlobEnd, blob_key, false); // encryption
}

blob_t RSA_Decryptor::Decrypt(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, const RSA_Key& key)
{
    blob_t blob_key = key.GetKey();

    return DoRSA(inputBlobStart, inputBlobEnd, blob_key, true); // decryption
}
