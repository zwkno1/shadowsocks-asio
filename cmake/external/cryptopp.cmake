
include (ExternalProject)

set(DOWNLOAD_LOCATION "${CMAKE_CURRENT_BINARY_DIR}/external/downloads" CACHE STRING "default download dir")

set(CryptoPP_TAG 8_1_0)
set(CryptoPP_URL https://github.com/weidai11/cryptopp/archive/CRYPTOPP_${CryptoPP_TAG}.tar.gz)
set(CryptoPP_MD5 a1095f0ceb5cd1186ccd5c253ee2bbfd)

set(CryptoPP_INSTALL ${CMAKE_CURRENT_BINARY_DIR}/external/CryptoPP/install)
set(CryptoPP_INCLUDE_DIRS ${CryptoPP_INSTALL}/include)
set(CryptoPP_LIBRARIES ${CryptoPP_INSTALL}/lib/libcryptopp.a)

ExternalProject_Add(CryptoPP
	PREFIX external/CryptoPP
	DOWNLOAD_DIR "${DOWNLOAD_LOCATION}"
	#GIT_REPOSITORY ${CryptoPP_URL}
	#GIT_TAG ${CryptoPP_TAG}
	URL ${CryptoPP_URL}
	URL_MD5 ${CryptoPP_MD5}
	CONFIGURE_COMMAND ""
	BUILD_IN_SOURCE 1
	BUILD_BYPRODUCTS ${CryptoPP_LIBRARIES}
	BUILD_COMMAND $(MAKE) 
	#INSTALL_DIR ${CryptoPP_INSTALL}
	INSTALL_COMMAND PREFIX=${CryptoPP_INSTALL} $(MAKE) install
	)

