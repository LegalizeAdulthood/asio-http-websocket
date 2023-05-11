add_executable(asio-websocket-client client.cpp)
target_link_libraries(asio-websocket-client PUBLIC boost::beast OpenSSL)
if(WIN32)
    target_compile_options(asio-websocket-client PUBLIC $<$<CONFIG:Debug>:/bigobj>)
endif()

add_executable(asio-websocket-server server.cpp)
target_link_libraries(asio-websocket-server PUBLIC boost::beast OpenSSL)
if(WIN32)
    target_compile_options(asio-websocket-server PUBLIC $<$<CONFIG:Debug>:/bigobj>)
endif()

set_target_properties(asio-websocket-client asio-websocket-server PROPERTIES FOLDER WebSocket)
