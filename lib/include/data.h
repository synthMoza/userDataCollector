#ifndef DATA_LIB_HEADER
#define DATA_LIB_HEADER

#include "types.h"

namespace udc
{

/*
    Basic class for classes to be serializable, defines such methods as Serialize and Deserialize.
*/
class IData
{
public:
    /// @brief Serialize class into blob
    /// @return Blob containing packed class data
    virtual blob_t Serialize() = 0;
    /// @brief Deserialize given blob and put data into this class
    /// @param blob Input blob with serialized data
    virtual void Deserialize(blob_t& blob) = 0;
    
    virtual ~IData();
};

}

#endif // #define DATA_LIB_HEADER
 