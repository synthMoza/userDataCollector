#ifndef CRYPTOR_LIB_HEADER
#define CRYPTOR_LIB_HEADER

#include <type_traits>
#include "types.h"

namespace udc
{

template <typename KeyValue>
class IBaseKey
{
public:
    virtual void SetKey(const KeyValue& value) { static_cast<void>(value); };
};

template <typename KeyValue>
class IPublicKey : public virtual IBaseKey<KeyValue>
{
public:
    virtual KeyValue GetKeyForEncryption() const = 0;

    virtual ~IPublicKey() {}
};

template <typename KeyValue>
class IPrivateKey : public virtual IBaseKey<KeyValue>
{
public:
    virtual KeyValue GetKeyForDecryption() const = 0;

    virtual ~IPrivateKey() {}
};

template <typename KeyValue>
class IKey : public IPublicKey<KeyValue>, public IPrivateKey<KeyValue>
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
    virtual blob_t Encrypt(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, const PublicKeyType& key) = 0;

    virtual ~IEncryptor() {}
};

template <typename PrivateKeyType>
class IDecryptor
{
public:
    using private_key_type = PrivateKeyType;

    virtual blob_t Decrypt(const blob_t& inputBlob, const PrivateKeyType& key) = 0;
    virtual blob_t Decrypt(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, const PrivateKeyType& key) = 0;

    virtual ~IDecryptor() {}
};

template <typename KeyType>
class ICryptor : public IEncryptor<KeyType>, public IDecryptor<KeyType>
{
public:
    using key_type = KeyType;
};


class DummyKey : public IKey<int>
{
public:
    virtual int GetKeyForEncryption() const override { return 0; };
    virtual int GetKeyForDecryption() const override { return 0; };
};

class DummyCryptor : public ICryptor<DummyKey>
{
public:
    virtual blob_t Encrypt(const blob_t& inputBlob, const DummyKey& key) override 
    { 
        static_cast<void>(key); // unused parameter
        return inputBlob; 
    }
    virtual blob_t Encrypt(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, const DummyKey& key) override 
    { 
        static_cast<void>(key); // unused parameter
        return blob_t(inputBlobStart, inputBlobEnd); 
    }
    virtual blob_t Decrypt(const blob_t& inputBlob, const DummyKey& key) override 
    { 
        static_cast<void>(key); // unused parameter
        return inputBlob; 
    }
    virtual blob_t Decrypt(const blob_const_iterator_t& inputBlobStart, const blob_const_iterator_t& inputBlobEnd, const DummyKey& key) override 
    { 
        static_cast<void>(key); // unused parameter
        return blob_t(inputBlobStart, inputBlobEnd); 
    }
};

}

#endif // #define CRYPTOR_LIB_HEADER
 