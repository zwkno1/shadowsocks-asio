#pragma once

#include <botan/stream_cipher.h>
#include <botan/auto_rng.h>

#include <shadowsocks/context.h>

namespace shadowsocks
{

class context
{
    struct engine
    {
        std::unique_ptr<Botan::StreamCipher> cipher_;
        size_t iv_wanted_;
        std::vector<uint8_t> iv_;
    };

public:
    context(const std::string & algo_spec, const std::vector<uint8_t> & key)
    {
        for(auto & i : engine_)
        {
            i.cipher_ = Botan::StreamCipher::create_or_throw(algo_spec);
            // todo: process failed later
            i.cipher_->set_key(key);
            i.iv_wanted_ = i.cipher_->default_iv_length();
            i.iv_.resize(i.cipher_->default_iv_length());
        }
        Botan::AutoSeeded_RNG{}.randomize(engine_[1].iv_.data(), engine_[1].iv_.size());
    }

    std::array<engine, 2> engine_;
};

}
