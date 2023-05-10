cmake_minimum_required(VERSION 3.22 FATAL_ERROR)

project(asio-http-websocket)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
find_package(BoostAsio)
find_package(BoostBeast)
find_package(RapidJSON CONFIG REQUIRED)
find_package(OpenSSL)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

add_subdirectory(http)
add_subdirectory(websocket)
add_subdirectory(comicsdb)
