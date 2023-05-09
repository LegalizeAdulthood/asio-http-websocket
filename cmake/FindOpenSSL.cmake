include(FindPackageHandleStandardArgs)

find_library(OPENSSL_LIB libssl.lib)
find_library(CRYPTO_LIB libcrypto.lib)
find_path(OPENSSL_INCLUDE openssl/opensslconf.h)

find_package_handle_standard_args(OpenSSL REQUIRED_VARS OPENSSL_LIB CRYPTO_LIB OPENSSL_INCLUDE)

if(OpenSSL_FOUND)
    add_library(crypto STATIC IMPORTED)
    target_include_directories(crypto INTERFACE ${OPENSSL_INCLUDE})
    set_target_properties(crypto PROPERTIES IMPORTED_LOCATION ${CRYPTO_LIB})

    add_library(OpenSSL STATIC IMPORTED)
    target_include_directories(OpenSSL INTERFACE ${OPENSSL_INCLUDE})
    set_target_properties(OpenSSL PROPERTIES IMPORTED_LOCATION ${OPENSSL_LIB})
    target_link_libraries(OpenSSL INTERFACE crypto)
endif()
