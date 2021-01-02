#pragma once

#include <shadowsocks/asio.h>

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
    cipher_buffer_too_short,
};

namespace detail
{
    
class cipher_category : public error_category
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
          return "cipher algo not found";
      if(value == cipher_need_more)
          return "cipher need more";
      if(value == cipher_aead_invalid_block_size)
          return "cipher aread invalid block size";
      if(value == cipher_aead_decrypt_verify_failed)
          return "cipher aead decrypt verify failed";
      if(value == cipher_buffer_too_short)
          return "cipher buffer too short";
      
      return "cipher unknown error";
  }
};

} // namespace detail

const error_category & get_cipher_category()
{
    static detail::cipher_category instance;
    return instance;
}

inline error_code make_error_code(cipher_errors e)
{
  return error_code(static_cast<int>(e), get_cipher_category());
}

} // namespace error
} // namespace shadowsocks

namespace boost
{
namespace system
{
    
template<>
struct is_error_code_enum<shadowsocks::error::cipher_errors> 
{
    static const bool value = true;
};

} // namespace system
} // namespace boost
