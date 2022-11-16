#ifndef CRYPTOR_LIB_HEADER
#define CRYPTOR_LIB_HEADER

#include <type_traits>
#include "types.h"

namespace udc
{

/*
    TODO (eganian.aa@phystech.edu):
    
    Come up with a cryptors interface, take into consideration - 
    they have to be flexible enough, so maybe there might be a
    separate "key_generator.h" and KeyGenerator might be a template
    parameter. They have to have, as a part of their interface, something
    like this:
        blob_t Encrypt(blob_t& inputBlob);
        blob_t Decrypt(blob_t& inputBlob);

*/

template <typename KeyValue>
class IPublicKey
{
public:
    virtual KeyValue GetKeyForEncryption() = 0;
    virtual KeyValue GetKeyForTestingSignature() = 0;

    virtual ~IPublicKey() {};
};

template <typename KeyValue>
class IPrivateKey
{
public:
    virtual KeyValue GetKeyForDecryption() = 0;
    virtual KeyValue GetKeyForMakingSignature() = 0;

    virtual ~IPrivateKey() {};
};

template <typename PublicKeyValue, typename PrivateKeyValue>
class IKey : public IPublicKey<PublicKeyValue>, public IPrivateKey<PrivateKeyValue>
{ };

template <typename PublicKeyValue, typename PrivateKeyValue>
class IKeyGenerator
{
public:
    virtual void Generate() = 0;

    virtual IPublicKey<PublicKeyValue>& GetPublicKey() = 0;
    virtual IPrivateKey<PrivateKeyValue>& GetPrivateKey() = 0;
};

template <typename KeyValue>
class IEncryptor
{
public:
    virtual blob_t Encrypt(const blob_t& inputBlob, const IPublicKey<KeyValue>& key) = 0;
    virtual bool   TestSignature(blob_t& inputBlob, const IPublicKey<KeyValue>& key) = 0;

    virtual ~IEncryptor() {}
};

template <typename KeyValue>
class IDecryptor
{
public:
    virtual blob_t Decrypt(blob_t& inputBlob, const IPrivateKey<KeyValue>& key) = 0;
    virtual blob_t MakeSignature(blob_t& inputBlob, const IPrivateKey<KeyValue>& key) = 0;

    virtual ~IDecryptor() {}
};

template <typename PublicKeyValue, typename PrivateKeyValue>
class ICryptor : IEncryptor<PublicKeyValue>, IDecryptor<PrivateKeyValue>
{ };


class DummyKey : public IKey<void, void>
{
public:
    virtual void GetKeyForEncryption() override {};
    virtual void GetKeyForTestingSignature() override {};
    virtual void GetKeyForDecryption() override {};
    virtual void GetKeyForMakingSignature() override {};
};

class DummyCryptor : ICryptor<void, void>
{
public:
    virtual blob_t Encrypt(const blob_t& inputBlob, const IPublicKey<void>& key) override { return inputBlob; }
    virtual bool   TestSignature(blob_t& inputBlob, const IPublicKey<void>& key) override { return true; }

    virtual blob_t Decrypt(blob_t& inputBlob, const IPrivateKey<void>& key) override { return inputBlob; }
    virtual blob_t MakeSignature(blob_t& inputBlob, const IPrivateKey<void>& key) override { return inputBlob; }
};

}

#endif // #define CRYPTOR_LIB_HEADER
 