#include <string>
#include <chrono>
#include <iostream>

#include <file_data.h>
#include <double_cryptor.h>
#include <RSA_cryptor.h>
#include <AES128_cryptor.h>


/*
    In these tests, we measure how much it takes to encrypt given file and the size of the output file.
    Test inputs file names are hard-coded, files themselves are generated before the actual test
*/

const std::string fileNames[] = {
    "test_file_32MB.dat",
    "test_file_128MB.dat",
    "test_file_256MB.dat",
    "test_file_512MB.dat",
    "test_file_1GB.dat",
    "test_file_2GB.dat",
};

using clock_type = std::chrono::high_resolution_clock;

using namespace udc;

int main()
{
    // public/private keys are created before-hand (gpg will generate them off-test, too)
    RSA_KeyGenerator keyGenRSA;
    keyGenRSA.Generate();

    std::cout << "Measuring encrypting time using UDC" << std::endl;

    // simulate encryption from start to finish, create all object over and over again
    for (auto& fileName : fileNames)
    {
        auto start = clock_type::now();
        // ============================

        // Generate random key 
        AES128_KeyGenerator keyGenAES128;
        keyGenAES128.Generate();

        // Read file into memory
        InputFileData inputFileData(fileName);

        // Encrypt file content
        DoubleEncryptor<AES128_Cryptor, RSA_Encryptor> doubleEncryptor;
        blob_t encryptedData = doubleEncryptor.Encrypt(inputFileData.Serialize(), {keyGenAES128.GetPublicKey(), keyGenRSA.GetPublicKey()});

        // Write to output file
        OutputFileData outputFile(std::string(fileName) + ".encrypted");
        outputFile.Deserialize(encryptedData);

        // ============================
        auto end = clock_type::now();

        std::cout << "File Name: " << fileName << ", output size = " << encryptedData.size() << 
            " bytes, ellapsed time = " << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() / 1000.f << " s" << std::endl;
    }

    return 0;
}