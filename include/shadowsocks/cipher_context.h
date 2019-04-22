#pragma once

#include <botan/stream_cipher.h>
#include <botan/aead.h>
#include <botan/auto_rng.h>

#include <shadowsocks/cipher_context.h>

namespace shadowsocks
{

struct cipher_info
{
    enum cipher_type : uint8_t
    {
        cipher_stream,
        cipher_aead,
    };

    cipher_type type;
    std::string algo;
    size_t key_length;
    size_t iv_length;

    // only for AEAD
    size_t salt_length;
    size_t tag_length;
};

class cipher
{
public:
    virtual size_t encrypt(uint8_t * in, uint8_t * out, size_t size) = 0;
    virtual size_t decrypt(uint8_t * in, uint8_t * out, size_t & size) = 0;
};

class stream_cipher : public cipher
{
    struct cipher_impl
    {
        bool init_;
        size_t iv_length_;
        std::unique_ptr<Botan::StreamCipher> cipher_;
    };

public:
    stream_cipher(const cipher_info & info, const std::vector<uint8_t> & key)
    {
        for(auto & i : impl_)
        {
            i.init_ = false;

            i.cipher_ = Botan::StreamCipher::create_or_throw(info.algo);

            i.cipher_->set_key(key);

            i.iv_length_ = info.iv_length;
        }
    }

    size_t encrypt(uint8_t *in, uint8_t *out, size_t size) override
    {
        size_t result = size;
        if(!impl_[1].init_)
        {
            Botan::AutoSeeded_RNG{}.randomize(out, impl_[1].iv_length_);
            impl_[1].cipher_->set_iv(out, impl_[1].iv_length_);

            impl_[1].init_ = true;
            out += impl_[1].iv_length_;
            result += impl_[1].iv_length_;
        }

        impl_[1].cipher_->cipher(in, out, size);
        return result;
    }

    size_t decrypt(uint8_t *in, uint8_t *out, size_t & size) override
    {
        if(!impl_[0].init_)
        {
            if(size < impl_[0].iv_length_)
                return 0;

            impl_[0].cipher_->set_iv(in, impl_[0].iv_length_);

            impl_[0].init_ = true;
            in += impl_[0].iv_length_;
            size -= impl_[0].iv_length_;
        }

        size_t result = size;
        impl_[0].cipher_->cipher(in, out, size);
        size = 0;
        return result;
    }

private:
    std::array<cipher_impl, 2> impl_;
};

class aead_cipher : public cipher
{
    struct cipher_impl
    {
        bool init_;
        size_t salt_length_;
        size_t tag_length_;
        std::vector<uint8_t> iv_;
        std::unique_ptr<Botan::AEAD_Mode> cipher_;
        Botan::secure_vector<uint8_t> buf_;
    };

public:
    aead_cipher(const cipher_info & info, const std::vector<uint8_t> & key)
    {
        Botan::Cipher_Dir dir = Botan::DECRYPTION;
        for(auto & i : impl_)
        {
            i.init_ = false;

            i.cipher_ = Botan::AEAD_Mode::create_or_throw(info.algo, dir);

            if(dir == Botan::DECRYPTION)
            {
                dir = Botan::ENCRYPTION;
            }

            i.cipher_->set_key(key);
            i.tag_length_ = info.tag_length;
            i.salt_length_ = info.salt_length;
            i.iv_.assign(info.iv_length, uint8_t{0});
        }
    }

    size_t encrypt(uint8_t *in, uint8_t *out, size_t size) override
    {
        uint8_t * out_begin = out;

        if(!impl_[1].init_)
        {
            Botan::AutoSeeded_RNG{}.randomize(out, impl_[1].salt_length_);
            impl_[1].cipher_->set_associated_data(out, impl_[1].salt_length_);

            impl_[1].init_ = true;
            out += impl_[1].salt_length_;
        }

        auto & buf = impl_[1].buf_;
        // enc length. length < 0x3fff
        impl_[1].cipher_->start(impl_[1].iv_.data(), impl_[1].iv_.size());
        buf.resize(2);
        buf[0] = (size >> 8) & 0x3f;
        buf[1] = size & 0xff;
        impl_[1].cipher_->finish(buf);
        inc_iv(1);
        std::memcpy(out, buf.data(), buf.size());
        out += buf.size();

        // enc data
        impl_[1].cipher_->start(impl_[1].iv_.data(), impl_[1].iv_.size());
        buf.resize(size);
        std::memcpy(buf.data(), in, size);
        impl_[1].cipher_->finish(buf);
        inc_iv(1);
        std::memcpy(out, buf.data(), buf.size());
        out += buf.size();
        return  out - out_begin;
    }

    size_t decrypt(uint8_t *in, uint8_t *out, size_t &size) override
    {

    }

    void inc_iv(int i)
    {
        uint16_t c = 1;
        for (auto & i : impl_[i].iv_)
        {
            c += i;
            i = c & 0xff;
            c >>= 8;
        }
    }

    cipher_impl impl_[2];
};

class cipher_context
{
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
