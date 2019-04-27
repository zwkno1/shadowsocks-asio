#pragma once

#include <boost/system/error_code.hpp>
#include <boost/asio/buffer.hpp>

#include <botan/stream_cipher.h>
#include <botan/auto_rng.h>
#include <botan/aead.h>

#include <shadowsocks/cipher_context.h>
#include <shadowsocks/error.h>

namespace shadowsocks
{
    
enum cipher_type : std::uint8_t
{
    STREAM,
    AEAD
};

struct cipher_info 
{
    // internal implementation name in Botan
    std::string name; 
    size_t key_length;
    size_t iv_length;
    cipher_type type;
    size_t salt_length; // only for AEAD
    size_t tag_length; // only for AEAD
};

class cipher_context
{
    struct engine
    {
        std::unique_ptr<Botan::AEAD_Mode> aead_;
        std::unique_ptr<Botan::StreamCipher> cipher_;
        bool init_;
        size_t iv_length_;
        Botan::secure_vector<uint8_t> buf_;
        size_t buf_size_;
    };

public:
    cipher_context(const cipher_info & info, const std::vector<uint8_t> & key)
    {
        for(auto & i : engine_)
        {
            i.cipher_ = Botan::StreamCipher::create(info.name);
            if(!i.cipher_)
            {
                throw error::make_error_code(error::cipher_algo_not_found);
            }
            
            i.cipher_->set_key(key);
            
            i.init_ = false;
            i.iv_length_ = info.iv_length;
            i.buf_size_ = 0;
        }
        engine_[0].buf_.resize(0x4ff);
    }
    
    boost::asio::const_buffer get_write_buffer()
    {
        auto & e = engine_[1];
        return boost::asio::const_buffer{e.buf_.data(), e.buf_.size()};
    }
    
    boost::asio::mutable_buffer get_read_buffer()
    {
        auto & e = engine_[0];
        return boost::asio::mutable_buffer{e.buf_.data() + e.buf_size_, e.buf_.size() - e.buf_size_};
    }
    
    void encrypt(const boost::asio::const_buffer & in, boost::system::error_code & ec)
    {
        auto & e = engine_[1];
        size_t offset = 0;
        if(!e.init_)
        {
            e.buf_.resize(e.iv_length_ + in.size());
            Botan::AutoSeeded_RNG{}.randomize(e.buf_.data(), e.iv_length_);
            e.cipher_->set_iv(e.buf_.data(), e.iv_length_);
            e.init_ = true;
            offset = e.iv_length_;
        }
        else
        {
            e.buf_.resize(in.size());
        }
        
        e.cipher_->cipher(reinterpret_cast<const uint8_t *>(in.data()), e.buf_.data() + offset, in.size());
    }
    
    void on_read(size_t bytes)
    {
        auto & e = engine_[0];
        e.buf_size_ += bytes;
    }
    
    void decrypt(boost::asio::mutable_buffer & out, boost::system::error_code & ec, size_t & bytes)
    {
        auto & e = engine_[0];
        size_t offset = 0;
        if(!e.init_)
        {
            if(e.buf_size_ < e.iv_length_)
                return;
            e.cipher_->set_iv(e.buf_.data(), e.iv_length_);
            e.init_ = true;
            offset += e.iv_length_;
            e.buf_size_ -= e.iv_length_;
        }
        bytes = std::min(out.size(), e.buf_size_);
        e.cipher_->cipher(
            reinterpret_cast<const uint8_t *>(e.buf_.data()) + offset,
            reinterpret_cast<uint8_t *>(out.data()),
            bytes);
        offset += bytes;
        e.buf_size_ -= bytes;
        if(offset > 0)
        {
            std::memcpy(e.buf_.data(), e.buf_.data() + offset, bytes);
        }
    }
    
private:
    std::array<engine, 2> engine_;
};

}
