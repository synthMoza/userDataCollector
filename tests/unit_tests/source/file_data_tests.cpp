#include <gtest/gtest.h>
#include <file_data.h>

#include <file_helper.h>

#include <string>
#include <fstream>

TEST(FileData, SimpleSerialization)
{
    // Create test file
    std::string fileContent = "YOU MAY ALLOC SOME MEMORE AND STORE SOMETHING THERE";
    
    std::string inputFileName = "input_test_file1.txt";
    std::string outputFileName = "output_test_file1.txt";

    std::ofstream fileStream(inputFileName);
    fileStream << fileContent;

    // Create input test file data
    udc::InputFileData inputFileData(inputFileName);
    auto blob = inputFileData.Serialize();

    // Create output test file data and compare
    udc::OutputFileData outputFileData(outputFileName);
    outputFileData.Deserialize(blob);

    // Compare files content (original = deserialized)
    EXPECT_TRUE(udc::helpers::CompareFileContent(inputFileName, outputFileName));
}
