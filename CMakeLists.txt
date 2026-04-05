cmake_minimum_required(VERSION 3.16)

project(Phantom LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)

find_package(spdlog CONFIG REQUIRED)
find_package(asio CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(httplib CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(GTest CONFIG REQUIRED)

file(GLOB_RECURSE ALL_SOURCES "${SRC_DIR}/*.cpp")

set(MAIN_FILE "${SRC_DIR}/main.cpp")
set(LOGIC_SOURCES ${ALL_SOURCES})
list(REMOVE_ITEM LOGIC_SOURCES "${MAIN_FILE}")


add_library(phantom_lib ${LOGIC_SOURCES})
target_include_directories(phantom_lib PUBLIC ${SRC_DIR})
target_link_libraries(phantom_lib PUBLIC 
    spdlog::spdlog 
    asio::asio 
    OpenSSL::SSL 
    OpenSSL::Crypto 
    httplib::httplib 
    nlohmann_json::nlohmann_json
)

add_executable(${PROJECT_NAME} "${MAIN_FILE}")
target_link_libraries(${PROJECT_NAME} PRIVATE phantom_lib)

enable_testing()
add_executable(phantom_tests tests/test_main.cpp)
target_link_libraries(phantom_tests PRIVATE phantom_lib GTest::gtest_main)
add_test(NAME AllTests COMMAND phantom_tests)

if(WIN32 AND MSVC)
    target_compile_definitions(phantom_lib PUBLIC
        _WIN32_WINNT=0x0A00
        WINVER=0x0A00
        OPENSSL_SUPPRESS_DEPRECATED
    )
endif()