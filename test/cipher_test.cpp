
#include "boost/asio/streambuf.hpp"
#include "boost/math/policies/policy.hpp"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "shadowsocks/asio.h"
#include "shadowsocks/cipher/detail/cipher.h"
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <shadowsocks/cipher/cipher.h>
#include <string>
#include <typeinfo>
#include <variant>

using namespace shadowsocks;

void test(const std::string &method, const std::string &password, size_t n,
          std::function<std::string()> generator) {
  auto info = make_cipher_info(method);
  auto key = make_cipher_key(*info, password);

  cipher_context context{*info, key};
  error_code ec;
  asio::streambuf buf;
  size_t nbytes;

  for (size_t i = 0; i < n; ++i) {
    auto str = generator();
    size_t enc_size;
    context.encrypt(asio::buffer(str.data(), str.size()), buf);
    std::string dec_str;
    dec_str.resize(str.size());
    context.decrypt(buf, asio::buffer(dec_str.data(), dec_str.size()), ec, nbytes);
    dec_str.resize(nbytes);

    if (ec || (str != dec_str)){
      std::cout << str << "," << dec_str << std::endl;
      size_t idx = 0;
      for(; idx < str.size(); ++idx){
        if(str[idx] != dec_str[idx]){
          break;
        }
      }
      std::cout << i << ", " << ec.message() << ", raw str size: " << str.size() << ", enc size: " << enc_size << ", dec size: " << dec_str.size() << ", idx: " << idx << std::endl;
      throw "bug";
    }
    buf.consume(buf.size());
  }
}

int main(int argc, char *argv[]) {
  const std::vector<std::string> cipher_methods = {
      "aes-128-cfb",
      "aes-192-cfb",
      "aes-256-cfb",
      "aes-128-ctr",
      "aes-192-ctr",
      "aes-256-ctr",
      "bf-cfb",
      "camellia-128-cfb",
      "camellia-192-cfb",
      "camellia-256-cfb",
      "cast5-cfb",
      "chacha20",
      "chacha20-ietf",
      "des-cfb",
      "idea-cfb",
      "rc2-cfb",
      "salsa20",
      "seed-cfb",
      "serpent-256-cfb",
      "chacha20-ietf-poly1305",
      "xchacha20-ietf-poly1305",
      "aes-128-gcm",
      "aes-192-gcm",
      "aes-256-gcm",
  };
  auto generator = []() -> std::string {
    //return "123456";
    std::string result;
    result.resize(rand() % 165536);
    for (auto &i : result) {
      i = rand();
    }
    return result;
  };

  for (auto & i : cipher_methods) {
      std::cout << "test method: " << i << std::endl;
      auto password = generator();
      test(i, password, 100, generator);
  }
  //std::cout << "stream" << std::endl;
  //test("aes-256-ctr", "123456", 10000, generator);
  //std::cout << "aead" << std::endl;
  //test("chacha20-ietf-poly1305", "123456", 10000, generator);

  return 0;
}