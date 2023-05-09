include(FindPackageHandleStandardArgs)

find_package(Boost)
if(Boost_FOUND)
    find_path(Boost_Asio_FOUND boost/asio.hpp PATHS ${Boost_INCLUDE_DIRS})
    if(Boost_Asio_FOUND)
        add_library(boost-asio INTERFACE)
        target_include_directories(boost-asio INTERFACE ${Boost_INCLUDE_DIRS})
        if(WIN32)
            target_compile_definitions(boost-asio INTERFACE _WIN32_WINNT=0x0601)
        endif()
        add_library(boost::asio ALIAS boost-asio)
    endif()
endif()

find_package_handle_standard_args(BoostAsio
    REQUIRED_VARS Boost_Asio_FOUND Boost_INCLUDE_DIRS)
