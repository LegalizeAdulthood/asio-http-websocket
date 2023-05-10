add_executable(asio-http-client client.cpp)
target_link_libraries(asio-http-client PUBLIC boost::beast comicsdb)

add_executable(asio-http-server server.cpp)
target_link_libraries(asio-http-server PUBLIC boost::beast OpenSSL comicsdb)

set_target_properties(asio-http-client asio-http-server PROPERTIES FOLDER HTTP)
