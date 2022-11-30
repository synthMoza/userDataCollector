#include <gtest/gtest.h>

#include <cryptor.h>
#include <AES128_cryptor.h>
#include <RSA_cryptor.h>
#include <double_cryptor.h>
#include <SHA256_hash.h>
#include <hash_based_signature.h>
#include <PGP_cryptor.h>

using namespace udc;

TEST(DummyCryptor, SimpleEncrypt)
{
    DummyKey dummyKey{};
    DummyCryptor dummyCryptor{};
    
    blob_t testData = {0x1, 0x2, 0x3, 0x4, 0x5};
    
    EXPECT_EQ(dummyCryptor.Encrypt(testData, dummyKey), testData); // returns input blob
    EXPECT_EQ(dummyCryptor.Decrypt(testData, dummyKey), testData); // private dummy key == public dummy key
}

TEST(AES128_Cryptor, SimpleEncrypt)
{
    AES128_KeyGenerator KeyGen;
    KeyGen.Generate();
    AES128_Cryptor AES_128_Cryptor{};
    
    blob_t testData = {0x1, 0x2, 0x3, 0x4, 0x5};

    blob_t encryptedData = AES_128_Cryptor.Encrypt(testData, KeyGen.GetPublicKey());

    std::cout << "Encrypted array: ";

    for (size_t i = 0; i < encryptedData.size(); ++i)
        std::cout << static_cast<unsigned>(encryptedData[i]) << " ";
    
    std::cout << std::endl;

    EXPECT_EQ(AES_128_Cryptor.Decrypt(encryptedData, KeyGen.GetPrivateKey()), testData);
}

TEST(AES128_Cryptor, MediumEncrypt)
{
    AES128_KeyGenerator KeyGen;
    KeyGen.Generate();
    AES128_Cryptor AES_128_Cryptor{};
    constexpr size_t testDataSize = 10000;
    blob_t testData(testDataSize);
    for (size_t i = 0; i < testDataSize; ++i) {
        testData[i] = static_cast<byte_t>(i);
    }
    
    blob_t encryptedData = AES_128_Cryptor.Encrypt(testData, KeyGen.GetPublicKey());

    EXPECT_EQ(AES_128_Cryptor.Decrypt(encryptedData, KeyGen.GetPrivateKey()), testData);
}

TEST(RSA_Cryptor, SimpleEncrypt)
{
    RSA_KeyGenerator KeyGen;
    KeyGen.Generate();
    
    RSA_Encryptor RSA_encryptor;
    RSA_Decryptor RSA_decryptor;
    
    blob_t testData = {0x1, 0x2, 0x3, 0x4, 0x5};

    blob_t encryptedData = RSA_encryptor.Encrypt(testData, KeyGen.GetPublicKey());

    std::cout << "Encrypted array: ";

    for (size_t i = 0; i < encryptedData.size(); ++i)
        std::cout << static_cast<unsigned>(encryptedData[i]) << " ";
    
    std::cout << std::endl;

    EXPECT_EQ(RSA_decryptor.Decrypt(encryptedData, KeyGen.GetPrivateKey()), testData);
}

TEST(RSA_Cryptor, MediumEncrypt)
{
    RSA_KeyGenerator KeyGen;
    KeyGen.Generate();
    
    RSA_Encryptor RSA_encryptor;
    RSA_Decryptor RSA_decryptor;
    constexpr size_t testDataSize = 100000;
    blob_t testData(testDataSize);
    for (size_t i = 0; i < testDataSize; ++i) {
        testData[i] = static_cast<byte_t>(i);
    }
    
    blob_t encryptedData = RSA_encryptor.Encrypt(testData, KeyGen.GetPublicKey());

    EXPECT_EQ(RSA_decryptor.Decrypt(encryptedData, KeyGen.GetPrivateKey()), testData);
}


TEST(DoubleCryptor, SimpleEncrypt)
{
    RSA_KeyGenerator KeyGenRSA;
    KeyGenRSA.Generate();
    
    AES128_KeyGenerator KeyGenAES128;
    KeyGenAES128.Generate();

    DoubleEncryptor<AES128_Cryptor, RSA_Encryptor> doubleEncryptor;
    DoubleDecryptor<AES128_Cryptor, RSA_Decryptor> doubleDecryptor;
    
    blob_t testData = {0x1, 0x2, 0x3, 0x4, 0x5};

    blob_t encryptedData = doubleEncryptor.Encrypt(testData, std::pair<AES128_Key, RSA_PublicKey>(KeyGenAES128.GetPublicKey(), KeyGenRSA.GetPublicKey()));

    std::cout << "Encrypted array: ";

    for (size_t i = 0; i < encryptedData.size(); ++i)
        std::cout << static_cast<unsigned>(encryptedData[i]) << " ";
    
    std::cout << std::endl;

    EXPECT_EQ(doubleDecryptor.Decrypt(encryptedData, KeyGenRSA.GetPrivateKey()), testData);
}

TEST(DoubleCryptor, MediumEncrypt)
{
    RSA_KeyGenerator KeyGenRSA;
    KeyGenRSA.Generate();
    
    AES128_KeyGenerator KeyGenAES128;
    KeyGenAES128.Generate();

    DoubleEncryptor<AES128_Cryptor, RSA_Encryptor> doubleEncryptor;
    DoubleDecryptor<AES128_Cryptor, RSA_Decryptor> doubleDecryptor;
    
    constexpr size_t testDataSize = 100000;
    blob_t testData(testDataSize);
    for (size_t i = 0; i < testDataSize; ++i) {
        testData[i] = static_cast<byte_t>(i);
    }

    blob_t encryptedData = doubleEncryptor.Encrypt(testData, std::pair<AES128_Key, RSA_PublicKey>(KeyGenAES128.GetPublicKey(), KeyGenRSA.GetPublicKey()));

    EXPECT_EQ(doubleDecryptor.Decrypt(encryptedData, KeyGenRSA.GetPrivateKey()), testData);
}

TEST(SHA256, SimpleHash)
{
    SHA256_Hash hash_Creator;
    
    blob_t testData = {0x1, 0x2, 0x3, 0x4, 0x5};

    blob_t hash = hash_Creator.CalculateHash(testData);

    std::cout << "Array's hash: ";

    for (size_t i = 0; i < hash.size(); ++i)
        std::cout << static_cast<unsigned>(hash[i]) << " ";
    
    std::cout << std::endl;

    EXPECT_EQ(hash, hash_Creator.CalculateHash(testData));
}

TEST(SHA256, MediumHash)
{
    SHA256_Hash hash_Creator;
    
    constexpr size_t testDataSize = 100000;
    blob_t testData(testDataSize);
    for (size_t i = 0; i < testDataSize; ++i) {
        testData[i] = static_cast<byte_t>(i);
    }

    blob_t hash = hash_Creator.CalculateHash(testData);

    EXPECT_EQ(hash, hash_Creator.CalculateHash(testData));
}

TEST(HashBasedSignature, SimpleSignature)
{
    RSA_KeyGenerator KeyGenRSA;
    KeyGenRSA.Generate();

    HashBasedSignatureCreator<SHA256_Hash, RSA_Encryptor> hashCreator;
    HashBasedSignaturTester<SHA256_Hash, RSA_Decryptor> hashTester;
    
    blob_t testData = {0x1, 0x2, 0x3, 0x4, 0x5};

    blob_t signature = hashCreator.CreateSignature(testData, KeyGenRSA.GetPublicKey());

    std::cout << "Signature of array: ";

    for (size_t i = 0; i < signature.size(); ++i)
        std::cout << static_cast<unsigned>(signature[i]) << " ";
    
    std::cout << std::endl;

    EXPECT_EQ(hashTester.CheckSignature(testData, signature, KeyGenRSA.GetPrivateKey()), true);
}

TEST(HashBasedSignature, MediumSignature)
{
    RSA_KeyGenerator KeyGenRSA;
    KeyGenRSA.Generate();

    HashBasedSignatureCreator<SHA256_Hash, RSA_Encryptor> hashCreator;
    HashBasedSignaturTester<SHA256_Hash, RSA_Decryptor> hashTester;
    
    constexpr size_t testDataSize = 100000;
    blob_t testData(testDataSize);
    for (size_t i = 0; i < testDataSize; ++i) {
        testData[i] = static_cast<byte_t>(i);
    }

    blob_t signature = hashCreator.CreateSignature(testData, KeyGenRSA.GetPublicKey());

    EXPECT_EQ(hashTester.CheckSignature(testData, signature, KeyGenRSA.GetPrivateKey()), true);
}

TEST(PGPCryptor, SimpleEncrypt)
{
    RSA_KeyGenerator KeyGenRSA1, KeyGenRSA2;
    KeyGenRSA1.Generate();
    KeyGenRSA2.Generate();
    
    AES128_KeyGenerator KeyGenAES128;
    KeyGenAES128.Generate();


    PGP_Encryptor<HashBasedSignatureCreator<SHA256_Hash, RSA_Encryptor>, DoubleEncryptor<AES128_Cryptor, RSA_Encryptor>> pgpEncryptor;
    PGP_Decryptor<HashBasedSignaturTester<SHA256_Hash, RSA_Decryptor>, DoubleDecryptor<AES128_Cryptor, RSA_Decryptor>> pgpDecryptor;
    
    constexpr size_t testDataSize = 100000;
    blob_t testData(testDataSize);
    for (size_t i = 0; i < testDataSize; ++i) {
        testData[i] = static_cast<byte_t>(i);
    }

    PGPKeyData<RSA_PublicKey, RSA_PublicKey, AES128_Key> keyForEncryption;
    PGPKeyData<RSA_PrivateKey, RSA_PrivateKey, AES128_Key> keyForDecryption;


    keyForEncryption.m_bunch_of_private_keys.push_back(KeyGenRSA1.GetPublicKey());
    keyForEncryption.m_bunch_of_public_keys.push_back(KeyGenRSA2.GetPublicKey());
    keyForEncryption.m_session_key = KeyGenAES128.GetPublicKey();

    blob_t encryptedData = pgpEncryptor.Encrypt(testData, keyForEncryption);

    keyForDecryption.m_bunch_of_private_keys.push_back(KeyGenRSA2.GetPrivateKey());
    keyForDecryption.m_bunch_of_public_keys.push_back(KeyGenRSA1.GetPrivateKey());

    EXPECT_EQ(pgpDecryptor.Decrypt(encryptedData, keyForDecryption), testData);
}

TEST(PGPCryptor, MediumEncrypt)
{
    RSA_KeyGenerator KeyGenRSA1, KeyGenRSA2;
    KeyGenRSA1.Generate();
    KeyGenRSA2.Generate();
    
    AES128_KeyGenerator KeyGenAES128;
    KeyGenAES128.Generate();


    PGP_Encryptor<HashBasedSignatureCreator<SHA256_Hash, RSA_Encryptor>, DoubleEncryptor<AES128_Cryptor, RSA_Encryptor>> pgpEncryptor;
    PGP_Decryptor<HashBasedSignaturTester<SHA256_Hash, RSA_Decryptor>, DoubleDecryptor<AES128_Cryptor, RSA_Decryptor>> pgpDecryptor;
    
    blob_t testData = {0x1, 0x2, 0x3, 0x4, 0x5};

    PGPKeyData<RSA_PublicKey, RSA_PublicKey, AES128_Key> keyForEncryption;
    PGPKeyData<RSA_PrivateKey, RSA_PrivateKey, AES128_Key> keyForDecryption;


    keyForEncryption.m_bunch_of_private_keys.push_back(KeyGenRSA1.GetPublicKey());
    keyForEncryption.m_bunch_of_public_keys.push_back(KeyGenRSA2.GetPublicKey());
    keyForEncryption.m_session_key = KeyGenAES128.GetPublicKey();

    blob_t encryptedData = pgpEncryptor.Encrypt(testData, keyForEncryption);

    std::cout << "Encrypted array: ";

    for (size_t i = 0; i < encryptedData.size(); ++i)
        std::cout << static_cast<unsigned>(encryptedData[i]) << " ";
    
    std::cout << std::endl;

    keyForDecryption.m_bunch_of_private_keys.push_back(KeyGenRSA2.GetPrivateKey());
    keyForDecryption.m_bunch_of_public_keys.push_back(KeyGenRSA1.GetPrivateKey());

    EXPECT_EQ(pgpDecryptor.Decrypt(encryptedData, keyForDecryption), testData);
}