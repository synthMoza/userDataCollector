#ifndef FILE_HELPER_HEADER
#define FILE_HELPER_HEADER

#include <string>
#include <fstream>
#include <filesystem>

namespace udc
{

namespace helpers
{

/**
 * @brief Compares content of two files byte-by-byte
 * 
 * @param fileName1 first file name
 * @param fileName2 second file name
 * @return true files are equal
 * @return false files differ
 */
bool CompareFileContent(const std::string& fileName1, const std::string& fileName2)
{
    if (std::filesystem::file_size(fileName1) != std::filesystem::file_size(fileName2))
        return false;

    std::ifstream file1(fileName1, std::ios::binary);
    std::ifstream file2(fileName2, std::ios::binary);

    return std::equal(std::istreambuf_iterator<char>(file1.rdbuf()),
                    std::istreambuf_iterator<char>(),
                    std::istreambuf_iterator<char>(file2.rdbuf()));
}

}

}

#endif // #define FILE_HELPER_HEADER
 