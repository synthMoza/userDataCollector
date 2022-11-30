#ifndef SIGNATURE_LIB_HEADER
#define SIGNATURE_LIB_HEADER
#include "cryptor.h"

namespace udc
{

template <typename PrivateKey>
class ISignatureCreator
{
public:
    using private_key_type = PrivateKey;

    virtual blob_t CreateSignature(const blob_t& inputBlob, const PrivateKey& key) = 0;
    virtual blob_t CreateSignature(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, const PrivateKey& key) = 0;
};

template <typename PublicKey>
class ISignatureChecker
{
public:
    using public_key_type = PublicKey;

    virtual bool CheckSignature(const blob_t& inputBlob, const blob_t& inputSignature, const PublicKey& key) = 0;
    virtual bool CheckSignature(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd,
                                const blob_const_iterator_t& inputSignatureStart, const blob_const_iterator_t& inputSignatureEnd,
                                const PublicKey& key) = 0;
};

}
#endif // #define SIGNATURE_LIB_HEADER