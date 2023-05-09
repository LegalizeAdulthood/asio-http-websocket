add_executable(asio-websocket-client client.cpp)
target_link_libraries(asio-websocket-client PUBLIC boost::beast comicsdb)

add_executable(asio-websocket-server server.cpp)
target_link_libraries(asio-websocket-server PUBLIC boost::beast comicsdb)

set_target_properties(asio-websocket-client asio-websocket-server PROPERTIES FOLDER WebSocket)
