#ifndef HASH_BASED_SIGNATURE_LIB_HEADER
#define HASH_BASED_SIGNATURE_LIB_HEADER
#include "hash.h"
#include "signature.h"

namespace udc
{
template <typename HashCreator, typename Encryptor>
class HashBasedSignatureCreator : public ISignatureCreator<typename Encryptor::public_key_type>
{
    HashCreator m_hashCreator;
    Encryptor m_encryptor;
public:
    using private_signature_key_type = typename Encryptor::public_key_type;

    virtual blob_t CreateSignature(const blob_t& inputBlob, const private_signature_key_type& key) { return CreateSignature(inputBlob.begin(), inputBlob.end(), key); }
    virtual blob_t CreateSignature(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, const private_signature_key_type& key) 
    {
        return m_encryptor.Encrypt(m_hashCreator.CalculateHash(inputBlobStart, inputBlobEnd), key);
    }
};

template <typename HashCreator, typename Decryptor>
class HashBasedSignaturTester : public ISignatureChecker<typename Decryptor::private_key_type>
{
    HashCreator m_hashCreator;
    Decryptor m_decryptor;
public:
    using public_signature_key_type = typename Decryptor::private_key_type;

    virtual bool CheckSignature(const blob_t& inputBlob, const blob_t& inputSignature, const public_signature_key_type& key) { return CheckSignature(inputBlob.begin(), inputBlob.end(), inputSignature.begin(), inputSignature.end(), key); }
    virtual bool CheckSignature(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd,
                            const blob_const_iterator_t& inputSignatureStart, const blob_const_iterator_t& inputSignatureEnd,
                            const public_signature_key_type& key) 
    {
        return m_decryptor.Decrypt(inputSignatureStart, inputSignatureEnd, key) == m_hashCreator.CalculateHash(inputBlobStart, inputBlobEnd);
    }
};
}

#endif // #define HASH_BASED_SIGNATURE_LIB_HEADER