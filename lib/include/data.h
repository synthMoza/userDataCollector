#ifndef DATA_LIB_HEADER
#define DATA_LIB_HEADER

#include "types.h"

namespace udc
{

/**
 * @brief Base interface for classes to be serializable
 * 
 */
class ISerializableData
{
public:
    /**
     * @brief Serialize class into blob
     * 
     * @return blob_t containing packed class data
     */
    virtual blob_t Serialize() const = 0;
    
    virtual ~ISerializableData() {}
};

/**
 * @brief Base interface for classes to be deserializable
 * 
 */
class IDeserializableData
{
public:
    /**
     * @brief Deserialize given blob and put data into this class
     * 
     * @param blob input blob with serialized data
     */
    virtual void Deserialize(const blob_t& blob) = 0;
    
    virtual ~IDeserializableData() {}
};

/**
 * @brief Base interface for classes to be both serializable and deserializable.
 * 
 * Seperate classes are required for typical scenarios when client only wants to serialize data, and server only wants to deserialize data
 * It still requires both implementation (serializable/deserilizable) to be useful for client/server sides 
 */
class IData : public ISerializableData, public IDeserializableData
{
public:
    /**
     * @brief Serialize class into blob
     * 
     * @return blob_t containing packed class data
     */
    virtual blob_t Serialize() const override = 0;

    /**
     * @brief Deserialize given blob and put data into this class
     * 
     * @param blob input blob with serialized data
     */
    virtual void Deserialize(const blob_t& blob) override = 0;

    virtual ~IData() {}
};

template <typename T>
using is_serializable = std::enable_if_t<std::is_base_of_v<ISerializableData, T>, bool>;

template <typename T>
using is_deserializable = std::enable_if_t<std::is_base_of_v<IDeserializableData, T>, bool>;

template <typename T>
using is_idata = std::enable_if_t<std::is_base_of_v<IData, T>, bool>;

}

#endif // #define DATA_LIB_HEADER
 