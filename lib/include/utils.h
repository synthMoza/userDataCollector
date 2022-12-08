#ifndef UTILS_LIB_HEADER
#define UTILS_LIB_HEADER

#include "data.h"
#include "types.h"

namespace udc
{

template <typename T>
blob_t typeToBlob(const T& x)
{
    T buf = x;
    return blob_t(reinterpret_cast<const byte_t*>(&buf), reinterpret_cast<const byte_t*>(&buf) + sizeof(T));
}

template <typename T, is_serializable<T> = true>
blob_t VectorToBlob(const std::vector<T>& vec)
{
    size_t vecSize = vec.size();
    std::vector<blob_t> blobVec(vec.size());

    blob_t outputBlob = typeToBlob(vecSize);

    for (size_t i = 0; i < vec.size(); ++i)
    {
        blobVec[i] = vec[i].Serialize();
        blob_t buf = typeToBlob(blobVec[i].size());
        outputBlob.insert(outputBlob.end(), buf.begin(), buf.end());
    }

    for (size_t i = 0; i < vec.size(); ++i)
    {
        outputBlob.insert(outputBlob.end(), blobVec[i].begin(), blobVec[i].end());
    }

    return outputBlob;
}

template <typename T, is_deserializable<T> = true>
std::vector<T> BlobToVector(const blob_t& blob)
{
    size_t vecSize = *reinterpret_cast<const size_t*>(&blob[0]);
    std::vector<T> outVec(vecSize);

    std::vector<size_t> elemSize(vecSize);

    for (size_t i = 0; i < vecSize; ++i)
        elemSize[i] = *reinterpret_cast<const size_t*>(&blob[(i + 1) * sizeof(size_t)]);

    size_t curPos = sizeof(size_t) + vecSize * sizeof(size_t);

    for (size_t i = 0; i < vecSize; ++i)
    {
        outVec[i].Deserialize(blob_t(blob.begin() + curPos, blob.begin() + curPos + elemSize[i]));
        curPos += elemSize[i];
    }

    return outVec;
}

}
#endif // #ifndef UTILS_LIB_HEADER