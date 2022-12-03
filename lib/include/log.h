#include <iostream>


namespace mlog
{


std::string GetTime()
{
    auto end = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(end);
    std::string time = std::ctime(&end_time);
    time.pop_back();
    return time;
}

template<typename T>
void constexpr inline PrintDataInfo(T& data)
{
	    std::cout << "[" << GetTime() << "]: " <<  data;
}


};