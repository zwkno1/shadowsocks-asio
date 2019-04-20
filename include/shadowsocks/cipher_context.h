#pragma once

#include <botan/stream_cipher.h>
#include <botan/auto_rng.h>

#include <shadowsocks/cipher_context.h>

namespace shadowsocks
{

class cipher_context
{
    struct engine
    {
        std::unique_ptr<Botan::StreamCipher> cipher_;
        size_t iv_wanted_;
        std::vector<uint8_t> iv_;
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
