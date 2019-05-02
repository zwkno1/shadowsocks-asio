#pragma once

#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

namespace shadowsocks
{
    
namespace error
{
enum cipher_errors
{
    cipher_algo_not_found = 1,
    cipher_need_more,
    cipher_aead_invalid_block_size,
    cipher_aead_decrypt_verify_failed,
    cipher_buf_too_short,
};

namespace detail
{
    
class cipher_category : public boost::system::error_category
{
public: 
  const char* name() const noexcept
  { 
      return "shadowsocks.cipher";
  }
  
  std::string message(int value) const
  { 
      if(value == 0)
          return "success";
      if (value == cipher_algo_not_found)
          return "Cipher algo not found";
      if(value == cipher_need_more)
          return "Cipher need more";
      if(value == cipher_aead_invalid_block_size)
          return "Cipher aread block too long";
      if(value == cipher_aead_decrypt_verify_failed)
          return "Cipher aead decrypt verify failed";
      
      return "shadowsocks.cipher error";
  }
};

}

const boost::system::error_category & get_cipher_category()
{
    static detail::cipher_category instance;
    return instance;
}

inline boost::system::error_code make_error_code(cipher_errors e)
{
  return boost::system::error_code(static_cast<int>(e), get_cipher_category());
}

}
}

namespace boost
{
namespace system
{
    
template<>
struct is_error_code_enum<shadowsocks::error::cipher_errors> 
{
    static const bool value = true;
};

}
}
