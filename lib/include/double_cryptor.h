#ifndef RSA_CRYPTOR_LIB_HEADER
#define RSA_CRYPTOR_LIB_HEADER

#include "cryptor.h"

namespace udc
{
// NOTE: Key for SymCryptor SHOULD be IData
template <typename SymCryptor, typename ASymDecryptor>
class DoubleDecryptor : public IDecryptor<ASymDecryptor::private_key_type>
{
public:
    using asym_private_key_type = ASymDecryptor::private_key_type;

    virtual blob_t Decrypt(const blob_t& inputBlob, const asym_private_key_type& key);
    virtual blob_t MakeSignature(const blob_t& inputBlob, const asym_private_key_type& key)
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