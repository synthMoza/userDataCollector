#ifndef CRYPTOR_LIB_HEADER
#define CRYPTOR_LIB_HEADER

#include <type_traits>
#include "types.h"

namespace udc
{

template <typename KeyValue>
class IPublicKey
{
public:
    virtual KeyValue GetKeyForEncryption() const = 0;
    virtual KeyValue GetKeyForTestingSignature() const = 0;

    virtual ~IPublicKey() {}
};

template <typename KeyValue>
class IPrivateKey
{
public:
    virtual KeyValue GetKeyForDecryption() const = 0;
    virtual KeyValue GetKeyForMakingSignature() const = 0;

    virtual ~IPrivateKey() {}
};

template <typename PublicKeyValue, typename PrivateKeyValue>
class IKey : public IPublicKey<PublicKeyValue>, public IPrivateKey<PrivateKeyValue>
{ };

template <typename PublicKey, typename PrivateKey>
class IKeyGenerator
{
public:
    virtual void Generate() = 0;

    virtual PublicKey GetPublicKey() const = 0;
    virtual PrivateKey GetPrivateKey() const = 0;

    virtual ~IKeyGenerator() {}
};

template <typename KeyValue>
class IEncryptor
{
public:
    virtual blob_t Encrypt(const blob_t& inputBlob, const IPublicKey<KeyValue>& key) = 0;
    virtual bool   TestSignature(const blob_t& inputBlob, const IPublicKey<KeyValue>& key) = 0;

    virtual ~IEncryptor() {}
};

template <typename KeyValue>
class IDecryptor
{
public:
    virtual blob_t Decrypt(const blob_t& inputBlob, const IPrivateKey<KeyValue>& key) = 0;
    virtual blob_t MakeSignature(const blob_t& inputBlob, const IPrivateKey<KeyValue>& key) = 0;

    virtual ~IDecryptor() {}
};

template <typename PublicKeyValue, typename PrivateKeyValue>
class ICryptor : public IEncryptor<PublicKeyValue>, public IDecryptor<PrivateKeyValue>
{};


class DummyKey : public IKey<void, void>
{
public:
    virtual void GetKeyForEncryption() const override {};
    virtual void GetKeyForTestingSignature() const override {};
    virtual void GetKeyForDecryption() const override {};
    virtual void GetKeyForMakingSignature() const override {};
};

class DummyCryptor : public ICryptor<void, void>
{
public:
    virtual blob_t Encrypt(const blob_t& inputBlob, const IPublicKey<void>& key) override 
    { 
        static_cast<void>(key); // unused parameter
        return inputBlob; 
    }
    virtual bool   TestSignature(const blob_t& inputBlob, const IPublicKey<void>& key) override 
    { 
        static_cast<void>(key); // unused parameters
        static_cast<void>(inputBlob);
        
        return true; 
    }

    virtual blob_t Decrypt(const blob_t& inputBlob, const IPrivateKey<void>& key) override 
    { 
        static_cast<void>(key); // unused parameter
        return inputBlob; 
    }
    virtual blob_t MakeSignature(const blob_t& inputBlob, const IPrivateKey<void>& key) override
    { 
        static_cast<void>(key); // unused parameter
        return inputBlob;
    }
};

}

#endif // #define CRYPTOR_LIB_HEADER
 