
#define BOOST_TEST_MODULE example

#include <cstring>
#include <iostream>
#include <string>
#include <shadowsocks/asio.h>
#include <shadowsocks/cipher/cipher.h>
#include <boost/test/unit_test.hpp>


using namespace shadowsocks;

//BOOST_AUTO_TEST_SUITE(cipher_test)

std::string generator()
{
    std::string result;
    result.resize(rand() % 165536);
    for (auto &i : result) {
      i = rand();
    }
    return result;
}

void do_cipher_test(const std::string &method, size_t n) {
  
  auto password = generator();
  auto info = make_cipher_info(method);
  BOOST_CHECK(info != nullptr);
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

    BOOST_CHECK_EQUAL(ec, error_code{});
    BOOST_CHECK_EQUAL(str, dec_str);
    BOOST_CHECK_EQUAL(buf.size(), 0);
    buf.consume(buf.size());
  }
}

#define ADD_CIPHER_TEST_CASE(name, method) \
BOOST_AUTO_TEST_CASE(name) \
{ \
    do_cipher_test(method, 100); \
}

ADD_CIPHER_TEST_CASE(aes_128_cfb, "aes-128-cfb")
ADD_CIPHER_TEST_CASE(aes_192_cfb, "aes-192-cfb")
ADD_CIPHER_TEST_CASE(aes_256_cfb, "aes-256-cfb")
ADD_CIPHER_TEST_CASE(aes_128_ctr, "aes-128-ctr")
ADD_CIPHER_TEST_CASE(aes_192_ctr, "aes-192-ctr")
ADD_CIPHER_TEST_CASE(aes_256_ctr, "aes-256-ctr")
ADD_CIPHER_TEST_CASE(bf_cfb, "bf-cfb")
ADD_CIPHER_TEST_CASE(camellia_128_cfb, "camellia-128-cfb")
ADD_CIPHER_TEST_CASE(camellia_192_cfb, "camellia-192-cfb")
ADD_CIPHER_TEST_CASE(camellia_256_cfb, "camellia-256-cfb")
ADD_CIPHER_TEST_CASE(cast5_cfb, "cast5-cfb")
ADD_CIPHER_TEST_CASE(chacha20, "chacha20")
ADD_CIPHER_TEST_CASE(chacha20_ietf, "chacha20-ietf")
ADD_CIPHER_TEST_CASE(des_cfb, "des-cfb")
ADD_CIPHER_TEST_CASE(idea_cfb, "idea-cfb")
ADD_CIPHER_TEST_CASE(rc2_cfb, "rc2-cfb")
ADD_CIPHER_TEST_CASE(salsa20, "salsa20")
ADD_CIPHER_TEST_CASE(seed_cfb, "seed-cfb")
ADD_CIPHER_TEST_CASE(serpent_256_cfb, "serpent-256-cfb")
ADD_CIPHER_TEST_CASE(chacha20_ietf_poly1305, "chacha20-ietf-poly1305")
ADD_CIPHER_TEST_CASE(xchacha20_ietf_poly1305, "xchacha20-ietf-poly1305")
ADD_CIPHER_TEST_CASE(aes_128_gcm, "aes-128-gcm")
ADD_CIPHER_TEST_CASE(aes_192_gcm, "aes-192-gcm")
ADD_CIPHER_TEST_CASE(aes_256_gcm, "aes-256-gcm")

//BOOST_AUTO_TEST_SUITE_END()
