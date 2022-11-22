#ifndef DOUBLE_CRYPTOR_LIB_HEADER
#define DOUBLE_CRYPTOR_LIB_HEADER

#include <type_traits>
#include "data.h"
#include "cryptor.h"

namespace udc
{

// NOTE: Key for SymCryptor SHOULD be IData
template <typename SymCryptor, typename ASymDecryptor>
class DoubleDecryptor : public IDecryptor<typename ASymDecryptor::private_key_type>
{
public:
    using asym_private_key_type = typename ASymDecryptor::private_key_type;
    using sym_key_type = typename SymCryptor::key_type;

    virtual blob_t Decrypt(const blob_t& inputBlob, const asym_private_key_type& key) override;
    virtual blob_t MakeSignature(const blob_t& inputBlob, const asym_private_key_type& key) override
    {
        static_cast<void>(key); // unused parameter
        return inputBlob;
    }
};

// NOTE: Key for SymCryptor SHOULD be IData
template <typename SymCryptor, typename ASymEncryptor>
class DoubleEncryptor : public IEncryptor<std::pair<typename SymCryptor::key_type, typename ASymEncryptor::public_key_type>>
{
public:
    using asym_public_key_type = typename ASymEncryptor::public_key_type;
    using sym_key_type = typename SymCryptor::key_type;
    using double_key_type = std::pair<sym_key_type, asym_public_key_type>;

    virtual blob_t Encrypt(const blob_t& inputBlob, const double_key_type& key) override;
    virtual bool   TestSignature(const blob_t& inputBlob, const double_key_type& key) override
    {
        static_cast<void>(key); // unused parameters
        static_cast<void>(inputBlob);
        
        return true; 
    }
};



template <typename SymCryptor, typename ASymDecryptor>
blob_t DoubleDecryptor<SymCryptor, ASymDecryptor>::Decrypt(const blob_t& inputBlob, const asym_private_key_type& key)
{
    const size_t symKeySize = *reinterpret_cast<const size_t*>(&inputBlob[inputBlob.size() - sizeof(size_t)]);
    if (inputBlob.size() < sizeof(size_t) + symKeySize)
        throw std::logic_error("File to decrypt is too small\n");

    blob_t encryptedSymKey = blob_t(inputBlob.end() - sizeof(size_t) - symKeySize, inputBlob.end() - sizeof(size_t));

    ASymDecryptor decryptor;
    blob_t decryptedSymKeyData = decryptor.Decrypt(encryptedSymKey, key);
    
    sym_key_type symKey;
    symKey.Deserialize(decryptedSymKeyData);

    SymCryptor symDecryptor;
    return symDecryptor.Decrypt(blob_t(inputBlob.begin(), inputBlob.end() - sizeof(size_t) - symKeySize), symKey);
}


template <typename SymCryptor, typename ASymEncryptor>
blob_t DoubleEncryptor<SymCryptor, ASymEncryptor>::Encrypt(const blob_t& inputBlob, const double_key_type& key)
{
    SymCryptor symEncryptor;
    blob_t output = symEncryptor.Encrypt(inputBlob, key.first);

    ASymEncryptor asymEncryptor;
    blob_t encryptedKey = asymEncryptor.Encrypt(key.first.Serialize(), key.second);

    output.insert(output.end(), encryptedKey.begin(), encryptedKey.end());

    size_t encryptedKeySize = encryptedKey.size();
    blob_t sizeData = blob_t(reinterpret_cast<byte_t*>(&encryptedKeySize), reinterpret_cast<byte_t*>(&encryptedKeySize) + sizeof(size_t) / sizeof(byte_t));
    output.insert(output.end(), sizeData.begin(), sizeData.end());

    return output;
}

}
#endif // #define DOUBLE_CRYPTOR_LIB_HEADER