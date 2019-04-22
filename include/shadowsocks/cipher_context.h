#pragma once

#include <botan/stream_cipher.h>
#include <botan/aead.h>
#include <botan/auto_rng.h>

#include <shadowsocks/cipher_context.h>
#include <variant>

namespace shadowsocks
{

class cipher
{
public:
    virtual void encrypt(uint8_t * src, size_t src_size, uint8_t * dst, size_t dst_size) = 0;
    virtual void decrypt(uint8_t * src, size_t src_size, uint8_t * dst, size_t dst_size) = 0;
};

class stream_cipher : public cipher
{
    struct impl
    {
        bool started_;
        std::vector<uint8_t> iv_;
    std::unique_ptr<Botan::StreamCipher> impl_;

    };
public:
    stream_cipher(const std::string & algo_spec, const std::vector<uint8_t> & key, size_t iv_length)
    {

        i.cipher_ = Botan::StreamCipher::create(algo_spec);
        if(!i.cipher_)
        {
            //throw boost::system::system_error(msocks::errc::cipher_algo_not_found, msocks::socks_category());
        }

        if(!i.cipher_->valid_keylength(key.size()))
        {
                //throw boost::system::system_error(msocks::errc::cipher_keylength_invalid, msocks::socks_category());
            }
            i.cipher_->set_key(key);

            if(!i.cipher_->valid_iv_length(iv_length))
            {
                //throw boost::system::system_error(msocks::errc::cipher_ivlength_invalid, msocks::socks_category());
            }
            i.iv_wanted_ = iv_length;
            i.iv_.resize(iv_length);
        }
        Botan::AutoSeeded_RNG{}.randomize(engine_[1].iv_.data(), engine_[1].iv_.size());

    }

private:
};

class cipher_context
{
    struct engine
    {
        std::unique_ptr<Botan::AEAD_Mode>

        bool started_;
        std::vector<uint8_t> iv_;

        void inc_iv()
        {
            uint16_t c = 1;
            for (auto & i : iv_)
            {
                c += i;
                i = c & 0xff;
                c >>= 8;
            }
        }

        size_t encrypt_size(size_t)
        {

        }
    };

public:
    cipher_context(const std::string & algo_spec, const std::vector<uint8_t> & key, size_t iv_length)
    {
        for(auto & i : engine_)
        {
            i.cipher_ = Botan::StreamCipher::create(algo_spec);
            if(!i.cipher_)
            {
				//throw boost::system::system_error(msocks::errc::cipher_algo_not_found, msocks::socks_category());
            }
            
            if(!i.cipher_->valid_keylength(key.size()))
            {
				//throw boost::system::system_error(msocks::errc::cipher_keylength_invalid, msocks::socks_category());
            }
            i.cipher_->set_key(key);
            
            if(!i.cipher_->valid_iv_length(iv_length))
            {
				//throw boost::system::system_error(msocks::errc::cipher_ivlength_invalid, msocks::socks_category());
            }
            i.iv_wanted_ = iv_length;
            i.iv_.resize(iv_length);
        }
        Botan::AutoSeeded_RNG{}.randomize(engine_[1].iv_.data(), engine_[1].iv_.size());
    }

    std::array<engine, 2> engine_;
};

}
