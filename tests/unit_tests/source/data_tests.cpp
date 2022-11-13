#include <gtest/gtest.h>
#include <file_data.h>
#include <json_data.h>

#include <file_helper.h>

#include <string>
#include <fstream>

using namespace udc;
using namespace nlohmann;

TEST(FileData, SimpleSerialization)
{
    // Create test file
    std::string fileContent = "YOU MAY ALLOC SOME MEMORE AND STORE SOMETHING THERE";
    
    std::string inputFileName = "input_test_file1.txt";
    std::string outputFileName = "output_test_file1.txt";

    std::ofstream fileStream(inputFileName);
    fileStream << fileContent;

    // Create input test file data
    InputFileData inputFileData(inputFileName);
    auto blob = inputFileData.Serialize();

    // Create output test file data and compare
    OutputFileData outputFileData(outputFileName);
    outputFileData.Deserialize(blob);

    // Compare files content (original = deserialized)
    EXPECT_TRUE(helpers::CompareFileContent(inputFileName, outputFileName));
}

TEST(JsonData, SimpleSerialization)
{
    // Create test JSON
    std::string content = "{\"action\":\"alloc some memore\",\"purpose\":\"store something there\"}";

    // Create input json with content, serialize it
    json inputJson = json::parse(content);
    InputJsonData inputJsonData(inputJson);

    auto blob = inputJsonData.Serialize();

    // Create output json data, deserialize blob
    OutputJsonData outputJsonData{};
    outputJsonData.Deserialize(blob);

    // Compare json content (original = deserialized)
    EXPECT_EQ(outputJsonData.Dump(), content);
}
