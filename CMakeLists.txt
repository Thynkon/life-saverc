cmake_minimum_required(VERSION 3.10)

# set the project name and version
project(lifesaverc VERSION 1.1 LANGUAGES C)

find_library(LIB_SSH ssh)                                                                                                    
if(NOT LIB_SSH)
    message(FATAL_ERROR "libssh library not found")
endif()

find_library(LIB_ARCHIVE archive)                                                                                                    
if(NOT LIB_ARCHIVE)
    message(FATAL_ERROR "libarchive library not found")
endif()

# compilation flags
ADD_COMPILE_OPTIONS(-Wall -Werror)

# directory to look for header files
include_directories(src/include)

# source files
file(GLOB SOURCES "src/*.c")

# compiler constants
add_definitions(-DPACKAGE_VERSION="${CMAKE_PROJECT_VERSION}")
add_definitions(-DPACKAGE_NAME="${CMAKE_PROJECT_NAME}")
add_definitions(-DLIBSSH_STATIC)

# set executable name
add_executable(${CMAKE_PROJECT_NAME} ${SOURCES})
# link against libssh and libarchive
target_link_libraries(${CMAKE_PROJECT_NAME} -lssh -larchive)

# set package compression to tar.gz
set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}-${CMAKE_PROJECT_VERSION}")

set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")

# list of files that wont be in the package distribution
set(CPACK_SOURCE_IGNORE_FILES "/packaging*;/.git*;/build/;/.bzr/;~$;${CPACK_SOURCE_IGNORE_FILES}")
include(CPack)

# create dist rule (make dist)
add_custom_target(dist COMMAND ${CMAKE_MAKE_PROGRAM} package_source)

# install lifesaverc in /usr/local/bin
install(TARGETS ${CMAKE_PROJECT_NAME} DESTINATION bin)

# uninstall target
if(NOT TARGET uninstall)
	configure_file(
		"${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
		"${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
		IMMEDIATE @ONLY)

	add_custom_target(uninstall COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()
