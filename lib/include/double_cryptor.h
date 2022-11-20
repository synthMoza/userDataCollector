#ifndef RSA_CRYPTOR_LIB_HEADER
#define RSA_CRYPTOR_LIB_HEADER

#include "cryptor.h"

namespace udc
{
// NOTE: Key for SymCryptor SHOULD be IData
template <typename SymCryptor, typename ASymDecryptor, typename PrivateKeyType>
class DoubleDecryptor : public IDecryptor<PrivateKeyType>
{
public:
    virtual blob_t Decrypt(const blob_t& inputBlob, const PrivateKeyType& key);
    virtual blob_t MakeSignature(const blob_t& inputBlob, const PrivateKeyType& key)
    {
        static_cast<void>(key); // unused parameters
        static_cast<void>(inputBlob);
        
        return true; 
    }
};

// NOTE: Key for SymCryptor SHOULD be IData
template <typename SymCryptor, typename ASymEncryptor>
class DoubleEncryptor : public IEncryptor
{
public:
    virtual blob_t Encrypt(const blob_t& inputBlob, const PublicKeyType& key);
    virtual bool   TestSignature(const blob_t& inputBlob, const PublicKeyType& key)
    {
        static_cast<void>(key); // unused parameter
        return inputBlob;
    }
};

}
#endif // #define RSA_CRYPTOR_LIB_HEADER