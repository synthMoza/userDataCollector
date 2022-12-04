#ifndef PGP_CRYPTOR_LIB_HEADER
#define PGP_CRYPTOR_LIB_HEADER

#include <openssl/rand.h>

#include "double_cryptor.h"
#include "hash_based_signature.h"

namespace udc
{

template <typename PrivateKey, typename PublicKey, typename SymKey>
struct PGPKeyData
{
    std::vector<PublicKey> m_bunchOfPublicKeys;
    std::vector<PrivateKey> m_bunchOfPrivateKeys;
    SymKey m_sessionKey;
};

namespace detail
{
    template <typename T>
    T GenerateRandomNumber(T to)
    {
        T x;
        if (!RAND_bytes(reinterpret_cast<unsigned char*>(&x), sizeof(T)))
            throw std::runtime_error("Can't generate random number with OpenSSL\n");
        x = x % to;
        return x;
    }
}

template <typename SignatureCreator, typename DEncryptor>
class PGP_Encryptor : public IEncryptor<PGPKeyData<typename SignatureCreator::private_key_type, typename DEncryptor::asym_public_key_type, typename DEncryptor::sym_key_type>>
{
    SignatureCreator m_signCreator;
    DEncryptor m_doubleEncryptor;
public:
    using private_key_type = typename SignatureCreator::private_key_type;
    using asym_public_key_type = typename DEncryptor::asym_public_key_type;
    using sym_key_type = typename DEncryptor::sym_key_type;
    using pgp_key_type = PGPKeyData<private_key_type, asym_public_key_type, sym_key_type>;

    virtual blob_t Encrypt(const blob_t& inputBlob, const pgp_key_type& key) override { return Encrypt(inputBlob.begin(), inputBlob.end(), key); }
    virtual blob_t Encrypt(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, const pgp_key_type& key)
    {
        size_t privateId = detail::GenerateRandomNumber(key.m_bunchOfPrivateKeys.size());
        blob_t blobSignature = m_signCreator.CreateSignature(inputBlobStart, inputBlobEnd, key.m_bunchOfPrivateKeys[privateId]);
        size_t signatureSize = blobSignature.size();
        std::cout << "Signature created\n";

        blob_t signedBlob = blob_t(reinterpret_cast<byte_t*>(&privateId), reinterpret_cast<byte_t*>(&privateId) + sizeof(size_t) / sizeof(byte_t));
        blob_t signatureSizeBlob = blob_t(reinterpret_cast<byte_t*>(&signatureSize), reinterpret_cast<byte_t*>(&signatureSize) + sizeof(size_t) / sizeof(byte_t));
        signedBlob.insert(signedBlob.end(), signatureSizeBlob.begin(), signatureSizeBlob.end());
        signedBlob.insert(signedBlob.end(),  blobSignature.begin(), blobSignature.end());
        signedBlob.insert(signedBlob.end(), inputBlobStart, inputBlobEnd);

        size_t publicId = detail::GenerateRandomNumber(key.m_bunchOfPublicKeys.size());
        blob_t output = blob_t(reinterpret_cast<byte_t*>(&publicId), reinterpret_cast<byte_t*>(&publicId) + sizeof(size_t) / sizeof(byte_t));
        blob_t encryptedData = m_doubleEncryptor.Encrypt(signedBlob, { key.m_sessionKey, key.m_bunchOfPublicKeys[publicId] });
        output.insert(output.end(), encryptedData.begin(), encryptedData.end());

        std::cout << "Message encrypted\n";
        return output;
    }
};

template <typename SignatureChecker, typename DDecryptor>
class PGP_Decryptor : public IDecryptor<PGPKeyData<typename DDecryptor::asym_private_key_type, typename SignatureChecker::public_key_type, typename DDecryptor::sym_key_type>>
{
    SignatureChecker m_signChecker;
    DDecryptor m_doubleDecryptor;
public:
    using public_key_type = typename SignatureChecker::public_key_type;
    using asym_private_key_type = typename DDecryptor::asym_private_key_type;
    using sym_key_type = typename DDecryptor::sym_key_type;
    using pgp_key_type = PGPKeyData<asym_private_key_type, public_key_type, sym_key_type>;
    virtual blob_t Decrypt(const blob_t& inputBlob, const pgp_key_type& key) override { return Decrypt(inputBlob.begin(), inputBlob.end(), key); }
    virtual blob_t Decrypt(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, const pgp_key_type& key)
    {
        size_t privateId = *reinterpret_cast<const size_t*>(&(*inputBlobStart));

        if (privateId >= key.m_bunchOfPrivateKeys.size())
            throw std::logic_error("Asym private key ID is too big for decryption\n");
        
        blob_t decrypted_blob = m_doubleDecryptor.Decrypt(inputBlobStart + sizeof(size_t), inputBlobEnd, key.m_bunchOfPrivateKeys[privateId]);

        size_t publicId = *reinterpret_cast<size_t*>(&(decrypted_blob[0]));
        if (publicId >= key.m_bunchOfPublicKeys.size())
            throw std::logic_error("Asym public key ID is too big for checking signature\n");

        size_t signatureSize = *reinterpret_cast<size_t*>(&(decrypted_blob[sizeof(size_t)]));
        if (signatureSize >= decrypted_blob.size() - 2 * sizeof(size_t))
            throw std::logic_error("File to decrypt is too small\n");

        if (!m_signChecker.CheckSignature(decrypted_blob.begin() + 2 * sizeof(size_t) + signatureSize, decrypted_blob.end(), 
                                          decrypted_blob.begin() + 2 * sizeof(size_t), decrypted_blob.begin() + 2 * sizeof(size_t) + signatureSize,
                                          key.m_bunchOfPublicKeys[publicId]))
            throw std::runtime_error("File is corrupted and can't be decrypt\n");
        return blob_t(decrypted_blob.begin() + 2 * sizeof(size_t) + signatureSize, decrypted_blob.end());
    }
};

}

#endif // #define PGP_CRYPTOR_LIB_HEADER