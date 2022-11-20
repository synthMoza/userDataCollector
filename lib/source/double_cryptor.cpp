#include <double_cryptor.h>

using namespace udc;

template <typename SymCryptor, typename ASymDecryptor, typename PrivateKeyType>
blob_t DoubleDecryptor<SymCryptor, ASymDecryptor, PrivateKeyType>::Decrypt(const blob_t& inputBlob, const PrivateKeyType& key)
{
    
}