# Application logic
add_library(comicsdb
  comicsdb.h
  comicsdb.cpp
  comic.h
  comic.cpp
  json.h
  json.cpp
)
target_include_directories(comicsdb PUBLIC .)
target_link_libraries(comicsdb PUBLIC rapidjson)
