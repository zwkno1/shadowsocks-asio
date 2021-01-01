#pragma once

#include <atomic>

namespace shadowsocks {

template<typename T>
class counter 
{
public:
	counter() 
	{
		++get_counter();
	}

	~counter()
	{
		--get_counter();
	}

	inline static std::atomic<size_t> & get_counter() 
	{
		static std::atomic<size_t> c = 0;
		return c;
	}
};

} // namespace shadowsocks
