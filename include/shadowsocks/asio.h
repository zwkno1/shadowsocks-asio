#pragma once

#include <chrono>
#include <functional>
#include <memory>

#include <boost/asio.hpp>
#include <boost/asio/coroutine.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/noncopyable.hpp>
#include <boost/system/system_error.hpp>

#include <spdlog/spdlog.h>

namespace chrono = std::chrono;

using noncopyable = boost::noncopyable;
using error_code = boost::system::error_code;
using system_error = boost::system::system_error;

namespace asio = boost::asio;
using tcp = boost::asio::ip::tcp;
using udp = boost::asio::ip::udp;
using streambuf = boost::asio::streambuf;

#ifdef SHADOWSOCKS_DISABLE_THREADS

template <typename _Tp>
using shared_ptr = std::__shared_ptr<_Tp, std::_Lock_policy::_S_single>;

template <typename _Tp>
using enable_shared_from_this =
    std::__enable_shared_from_this<_Tp, std::_Lock_policy::_S_single>;

template <typename _Tp>
using weak_ptr = std::__weak_ptr<_Tp, std::_Lock_policy::_S_single>;

template <typename _Tp, typename... _Args>
inline shared_ptr<_Tp> make_shared(_Args &&... args) {
  return std::__make_shared<_Tp, std::_Lock_policy::_S_single, _Args...>(
      std::forward<_Args>(args)...);
}

#else

using std::enable_shared_from_this;
using std::make_shared;
using std::shared_ptr;
using std::weak_ptr;

#endif

namespace boost {
namespace asio {
namespace external {

typedef asio::detail::socket_option::boolean<BOOST_ASIO_OS_DEF(SOL_SOCKET), SO_REUSEPORT> reuse_port;

} // namespace external

} // namespace asio
} // namespace boost
