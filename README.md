# shadowsocks-asio

a c++ shadowsocks server.

dependencies: crypto++ and boost.asio.

## build
```shell
git submodule init
git submodule update
mkdir build && cd build && cmake ..
make -j8
```

## run 
```shell
./ss-server -c server.json
```
