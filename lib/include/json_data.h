#ifndef JSON_DATA_HEADER
#define JSON_DATA_HEADER

#include <data.h>

#include <nlohmann/json.hpp>

namespace udc
{

/**
 * @brief Input Json Data allows to serialize json data
 * 
 */
class InputJsonData : public ISerializableData
{
    nlohmann::json m_json;
public:
    InputJsonData(const nlohmann::json& json) :
        m_json(json) {}

    blob_t Serialize() const override
    {
        auto jsonString = m_json.dump();
        return blob_t(jsonString.begin(), jsonString.end());
    }

    virtual ~InputJsonData() {}
};

/**
 * @brief Output Json Data allows to deserialize json data
 * 
 */
class OutputJsonData : public IDeserializableData
{
    nlohmann::json m_json;
public:
    OutputJsonData(const nlohmann::json& json) :
        m_json(json) {}

    OutputJsonData() {}

    void Deserialize(const blob_t& blob) override
    {
        std::string jsonDump(blob.begin(), blob.end());
        m_json = nlohmann::json::parse(jsonDump);
    }
    
    /**
     * @brief Get underlying JSON string
     * 
     * @return std::string JSON string
     */
    std::string Dump()
    {
        return m_json.dump();
    }

    virtual ~OutputJsonData() {}
};

}

#endif // #define JSON_DATA_HEADER
