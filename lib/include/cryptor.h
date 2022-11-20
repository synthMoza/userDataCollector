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


/*
TODO: fix double copy of keys when using generator

Example:

KeyGenerator.Generate();
key = KeyGenerator.GetPublicKey(); -> 1st copy

in some encryptor:
key.GetKeyForEncryption(); -> 2nd copy
*/
template <typename PublicKey, typename PrivateKey>
class IKeyGenerator
{
public:
    virtual void Generate() = 0;

    virtual PublicKey GetPublicKey() const = 0;
    virtual PrivateKey GetPrivateKey() const = 0;

    virtual ~IKeyGenerator() {}
};

template <typename KeyGenerator>
KeyGenerator MakeKeyGenerator()
{
    KeyGenerator keyGen;
    keyGen.Generate();
    return keyGen;
}

template <typename PublicKeyType>
class IEncryptor
{
public:
    using public_key_type = PublicKeyType;

    virtual blob_t Encrypt(const blob_t& inputBlob, const PublicKeyType& key) = 0;
    virtual bool   TestSignature(const blob_t& inputBlob, const PublicKeyType& key) = 0;

    virtual ~IEncryptor() {}
};

template <typename PrivateKeyType>
class IDecryptor
{
public:
    using private_key_type = PrivateKeyType;

    virtual blob_t Decrypt(const blob_t& inputBlob, const PrivateKeyType& key) = 0;
    virtual blob_t MakeSignature(const blob_t& inputBlob, const PrivateKeyType& key) = 0;

    virtual ~IDecryptor() {}
};

template <typename PublicKeyType, typename PrivateKeyType>
class ICryptor : public IEncryptor<PublicKeyType>, public IDecryptor<PrivateKeyType>
{};


class DummyKey : public IKey<void, void>
{
public:
    virtual void GetKeyForEncryption() const override {};
    virtual void GetKeyForTestingSignature() const override {};
    virtual void GetKeyForDecryption() const override {};
    virtual void GetKeyForMakingSignature() const override {};
};

class DummyCryptor : public ICryptor<DummyKey, DummyKey>
{
public:
    virtual blob_t Encrypt(const blob_t& inputBlob, const DummyKey& key) override 
    { 
        static_cast<void>(key); // unused parameter
        return inputBlob; 
    }
    virtual bool   TestSignature(const blob_t& inputBlob, const DummyKey& key) override 
    { 
        static_cast<void>(key); // unused parameters
        static_cast<void>(inputBlob);
        
        return true; 
    }

    virtual blob_t Decrypt(const blob_t& inputBlob, const DummyKey& key) override 
    { 
        static_cast<void>(key); // unused parameter
        return inputBlob; 
    }
    virtual blob_t MakeSignature(const blob_t& inputBlob, const DummyKey& key) override
    { 
        static_cast<void>(key); // unused parameter
        return inputBlob;
    }
};

}

#endif // #define CRYPTOR_LIB_HEADER
 