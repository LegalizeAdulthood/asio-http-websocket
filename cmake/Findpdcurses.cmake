include(FindPackageHandleStandardArgs)

find_library(PDCURSES_LIB pdcurses.lib)
find_path(PDCURSES_INCLUDE curses.h)

find_package_handle_standard_args(pdcurses REQUIRED_VARS PDCURSES_LIB PDCURSES_INCLUDE)

if(pdcurses_FOUND)
    add_library(pdcurses STATIC IMPORTED)
    target_include_directories(pdcurses INTERFACE ${PDCURSES_INCLUDE})
    set_target_properties(pdcurses PROPERTIES IMPORTED_LOCATION ${PDCURSES_LIB})
endif()
