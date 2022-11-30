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
    std::vector<PublicKey> m_bunch_of_public_keys;
    std::vector<PrivateKey> m_bunch_of_private_keys;
    SymKey m_session_key;
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
    SignatureCreator m_sign_creator;
    DEncryptor m_double_encryptor;
public:
    using private_key_type = typename SignatureCreator::private_key_type;
    using asym_public_key_type = typename DEncryptor::asym_public_key_type;
    using sym_key_type = typename DEncryptor::sym_key_type;
    using pgp_key_type = PGPKeyData<private_key_type, asym_public_key_type, sym_key_type>;

    virtual blob_t Encrypt(const blob_t& inputBlob, const pgp_key_type& key) override { return Encrypt(inputBlob.begin(), inputBlob.end(), key); }
    virtual blob_t Encrypt(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, const pgp_key_type& key)
    {
        size_t private_id = detail::GenerateRandomNumber(key.m_bunch_of_private_keys.size());
        blob_t blob_signature = m_sign_creator.CreateSignature(inputBlobStart, inputBlobEnd, key.m_bunch_of_private_keys[private_id]);
        size_t signature_size = blob_signature.size();

        blob_t signed_blob = blob_t(reinterpret_cast<byte_t*>(&private_id), reinterpret_cast<byte_t*>(&private_id) + sizeof(size_t) / sizeof(byte_t));
        blob_t signature_size_blob = blob_t(reinterpret_cast<byte_t*>(&signature_size), reinterpret_cast<byte_t*>(&signature_size) + sizeof(size_t) / sizeof(byte_t));
        signed_blob.insert(signed_blob.end(), signature_size_blob.begin(), signature_size_blob.end());
        signed_blob.insert(signed_blob.end(),  blob_signature.begin(), blob_signature.end());
        signed_blob.insert(signed_blob.end(), inputBlobStart, inputBlobEnd);

        size_t public_id = detail::GenerateRandomNumber(key.m_bunch_of_public_keys.size());
        blob_t output = blob_t(reinterpret_cast<byte_t*>(&public_id), reinterpret_cast<byte_t*>(&public_id) + sizeof(size_t) / sizeof(byte_t));
        blob_t encryptedData = m_double_encryptor.Encrypt(signed_blob, { key.m_session_key, key.m_bunch_of_public_keys[public_id] });
        output.insert(output.end(), encryptedData.begin(), encryptedData.end());
        return output;
    }
};

template <typename SignatureChecker, typename DDecryptor>
class PGP_Decryptor : public IDecryptor<PGPKeyData<typename DDecryptor::asym_private_key_type, typename SignatureChecker::public_key_type, typename DDecryptor::sym_key_type>>
{
    SignatureChecker m_sign_checker;
    DDecryptor m_double_decryptor;
public:
    using public_key_type = typename SignatureChecker::public_key_type;
    using asym_private_key_type = typename DDecryptor::asym_private_key_type;
    using sym_key_type = typename DDecryptor::sym_key_type;
    using pgp_key_type = PGPKeyData<asym_private_key_type, public_key_type, sym_key_type>;
    virtual blob_t Decrypt(const blob_t& inputBlob, const pgp_key_type& key) override { return Decrypt(inputBlob.begin(), inputBlob.end(), key); }
    virtual blob_t Decrypt(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, const pgp_key_type& key)
    {
        size_t private_id = *reinterpret_cast<const size_t*>(&(*inputBlobStart));

        if (private_id >= key.m_bunch_of_private_keys.size())
            throw std::logic_error("Asym private key ID is too big for decryption\n");
        
        blob_t decrypted_blob = m_double_decryptor.Decrypt(inputBlobStart + sizeof(size_t), inputBlobEnd, key.m_bunch_of_private_keys[private_id]);

        size_t public_id = *reinterpret_cast<size_t*>(&(decrypted_blob[0]));
        if (public_id >= key.m_bunch_of_public_keys.size())
            throw std::logic_error("Asym public key ID is too big for checking signature\n");

        size_t signature_size = *reinterpret_cast<size_t*>(&(decrypted_blob[sizeof(size_t)]));
        if (signature_size >= decrypted_blob.size() - 2 * sizeof(size_t))
            throw std::logic_error("File to decrypt is too small\n");

        if (!m_sign_checker.CheckSignature(decrypted_blob.begin() + 2 * sizeof(size_t) + signature_size, decrypted_blob.end(), 
                                          decrypted_blob.begin() + 2 * sizeof(size_t), decrypted_blob.begin() + 2 * sizeof(size_t) + signature_size,
                                          key.m_bunch_of_public_keys[public_id]))
            throw std::runtime_error("File is corrupted and can't be decrypt\n");
        return blob_t(decrypted_blob.begin() + 2 * sizeof(size_t) + signature_size, decrypted_blob.end());
    }
};

}

#endif // #define PGP_CRYPTOR_LIB_HEADER