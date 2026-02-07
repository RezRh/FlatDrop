# CMakeLists.txt
cmake_minimum_required(VERSION 3.4.1)

project(entry)

set(NATIVERENDER_ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR})

if(DEFINED OHOS_ARCH)
    set(ARCH ${OHOS_ARCH})
else()
    set(ARCH "arm64-v8a") # Default fallback
endif()

# Include directories
include_directories(${NATIVERENDER_ROOT_PATH}
                    ${NATIVERENDER_ROOT_PATH}/include)

# Add the Rust static library
add_library(hub STATIC IMPORTED)
set_target_properties(hub PROPERTIES IMPORTED_LOCATION
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../libs/${ARCH}/libhub.a)

# Create the shared library for NAPI
add_library(entry SHARED napi_init.cpp)

# Link libraries
target_link_libraries(entry PUBLIC libace_napi.z.so hub)
