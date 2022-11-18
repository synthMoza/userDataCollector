#include <gtest/gtest.h>

#include <cryptor.h>

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
