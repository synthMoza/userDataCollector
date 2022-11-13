#ifndef STREAM_DATA_LIB_HEADER
#define STREAM_DATA_LIB_HEADER

#include <fstream>
#include <vector>
#include <string>

#include "data.h"

namespace udc
{

/**
 * @brief File Data class provides interface for files to be easily serializable.
 * 
 */
class InputFileData : public ISerializableData
{
    std::ifstream m_inputFile;
public:
    /**
     * @brief Construct a new Input File Data object
     * 
     * @param inputFilePath path to the file to be serialized
     */
    InputFileData(const std::string& inputFilePath) :
        m_inputFile(inputFilePath, std::ios_base::in | std::ios_base::binary) {}

    blob_t Serialize() override
    {
        // Discover file size
        m_inputFile.seekg(0, std::ios::end);
        auto fileSize = m_inputFile.tellg();
        m_inputFile.seekg(0, std::ios::beg);

        // Reserve vector of bytes
        std::vector<byte_t> bytesBuffer(fileSize);

        // Read file into vector
        bytesBuffer.insert(bytesBuffer.begin(), std::istream_iterator<byte_t>(m_inputFile), std::istream_iterator<byte_t>());

        return bytesBuffer;
    }

    virtual ~InputFileData() {}
};

/**
 * @brief File Data class provides interface for files to be easily deserializable.
 * 
 */
class OutputFileData : public IDeserializableData
{
    std::ofstream m_outputFile;
public:
    /**
     * @brief Construct a new Output File Data object
     * 
     * @param outputFilePath path to the file to be serialized
     */
    OutputFileData(const std::string& outputFilePath) :
        m_outputFile(outputFilePath, std::ios_base::out | std::ios_base::binary) {}

    void Deserialize(blob_t& blob) override
    {
        m_outputFile.write(reinterpret_cast<char*>(&blob[0]), blob.size());
    }

    virtual ~OutputFileData() {}
};

}

#endif // #define STREAM_DATA_LIB_HEADER
 