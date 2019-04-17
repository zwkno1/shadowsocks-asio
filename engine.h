#pragma once

#include <botan/botan.h>
#include <botan/stream_cipher.h>
#include <botan/auto_rng.h>

#include <context.h>

namespace shadowsocks
{
namespace detail
{

class engine
{
    struct cipher_data
    {
        std::unique_ptr<Botan::StreamCipher> cipher_;
        size_t iv_wanted_;
        std::vector<uint8_t> iv_;
    };

public:
    engine(const context & ctx)
    {
        for(auto & i : cipher_data_)
        {
            i.cipher_ = Botan::StreamCipher::create(ctx.algo_spec);
            // todo: process failed later
            i.cipher_->set_key(ctx.key);
            i.iv_wanted_ = i.cipher_->default_iv_length();
            i.iv_.resize(i.cipher_->default_iv_length());
        }
        Botan::AutoSeeded_RNG{}.randomize(cipher_data_[1].iv_.data(), cipher_data_[1].iv_.size());
    }

    std::array<cipher_data, 2> cipher_data_;
};

}
}
