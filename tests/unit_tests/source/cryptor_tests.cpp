#include <gtest/gtest.h>

#include <cryptor.h>
#include <openssl_cryptors.h>

using namespace udc;

TEST(DummyCryptor, SimpleEncrypt)
{
    DummyKey dummyKey{};
    DummyCryptor dummyCryptor{};
    
    blob_t testData = {0x1, 0x2, 0x3, 0x4, 0x5};
    
    EXPECT_TRUE(dummyCryptor.TestSignature(testData, dummyKey)); // always true
    EXPECT_EQ(dummyCryptor.Encrypt(testData, dummyKey), testData); // returns input blob
    EXPECT_EQ(dummyCryptor.Decrypt(testData, dummyKey), testData); // private dummy key == public dummy key
    EXPECT_EQ(dummyCryptor.MakeSignature(testData, dummyKey), testData); // signature == input data
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
