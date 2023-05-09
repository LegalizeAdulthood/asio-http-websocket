include(FindPackageHandleStandardArgs)

find_package(Boost)
if(Boost_FOUND)
    find_path(Boost_Beast_FOUND boost/beast.hpp PATHS ${Boost_INCLUDE_DIRS})
    if(Boost_Beast_FOUND)
        add_library(boost-beast INTERFACE)
        target_include_directories(boost-beast INTERFACE ${Boost_INCLUDE_DIRS})
        if(WIN32)
            target_compile_definitions(boost-beast INTERFACE _WIN32_WINNT=0x0601)
        endif()
        target_link_libraries(boost-beast INTERFACE boost-asio)
        add_library(boost::beast ALIAS boost-beast)
    endif()
endif()

find_package_handle_standard_args(BoostBeast
    REQUIRED_VARS Boost_Beast_FOUND Boost_INCLUDE_DIRS)
