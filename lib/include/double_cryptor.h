#ifndef DOUBLE_CRYPTOR_LIB_HEADER
#define DOUBLE_CRYPTOR_LIB_HEADER

#include <type_traits>
#include "data.h"
#include "cryptor.h"

namespace udc
{

template <typename SymCryptor, typename ASymDecryptor, is_serializable<typename SymCryptor::key_type> = true>
class DoubleDecryptor : public IDecryptor<typename ASymDecryptor::private_key_type>
{
public:
    using asym_private_key_type = typename ASymDecryptor::private_key_type;
    using sym_key_type = typename SymCryptor::key_type;
    virtual blob_t Decrypt(const blob_t& inputBlob, const asym_private_key_type& key)  { return Decrypt(inputBlob.begin(), inputBlob.end(), key); }
    virtual blob_t Decrypt(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, const asym_private_key_type& key) override
    {
        const size_t symKeySize = *reinterpret_cast<const size_t*>(&(*(inputBlobEnd - sizeof(size_t))));
        size_t inputBlobSize = inputBlobEnd - inputBlobStart;
        if (inputBlobSize < sizeof(size_t) + symKeySize)
            throw std::logic_error("File to decrypt is too small\n");

        ASymDecryptor decryptor;
        blob_t decryptedSymKeyData = decryptor.Decrypt(inputBlobEnd - sizeof(size_t) - symKeySize, inputBlobEnd - sizeof(size_t), key);
        
        sym_key_type symKey;
        symKey.Deserialize(decryptedSymKeyData);

        SymCryptor symDecryptor;
        return symDecryptor.Decrypt(inputBlobStart, inputBlobEnd - sizeof(size_t) - symKeySize, symKey);
    }
};

template <typename SymCryptor, typename ASymEncryptor, is_deserializable<typename SymCryptor::key_type> = true>
class DoubleEncryptor : public IEncryptor<std::pair<typename SymCryptor::key_type, typename ASymEncryptor::public_key_type>>
{
public:
    using asym_public_key_type = typename ASymEncryptor::public_key_type;
    using sym_key_type = typename SymCryptor::key_type;
    using double_key_type = std::pair<sym_key_type, asym_public_key_type>;
    virtual blob_t Encrypt(const blob_t& inputBlob, const double_key_type& key)  { return Encrypt(inputBlob.begin(), inputBlob.end(), key); }
    virtual blob_t Encrypt(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, const double_key_type& key) override
    {
        SymCryptor symEncryptor;
        blob_t output = symEncryptor.Encrypt(inputBlobStart, inputBlobEnd, key.first);

        ASymEncryptor asymEncryptor;
        blob_t encryptedKey = asymEncryptor.Encrypt(key.first.Serialize(), key.second);

        output.insert(output.end(), encryptedKey.begin(), encryptedKey.end());

        size_t encryptedKeySize = encryptedKey.size();
        blob_t sizeData = blob_t(reinterpret_cast<byte_t*>(&encryptedKeySize), reinterpret_cast<byte_t*>(&encryptedKeySize) + sizeof(size_t) / sizeof(byte_t));
        output.insert(output.end(), sizeData.begin(), sizeData.end());

        return output;
    }
};


}
#endif // #define DOUBLE_CRYPTOR_LIB_HEADER