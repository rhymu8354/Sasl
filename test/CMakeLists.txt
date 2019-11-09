# CMakeLists.txt for SaslTests
#
# © 2019 by Richard Walters

cmake_minimum_required(VERSION 3.8)
set(This SaslTests)

set(Sources
    src/Client/LoginTests.cpp
    src/Client/PlainTests.cpp
    src/Client/ScramTests.cpp
)

add_executable(${This} ${Sources})
set_target_properties(${This} PROPERTIES
    FOLDER Tests
)

target_include_directories(${This} PRIVATE ..)

target_link_libraries(${This} PUBLIC
    Base64
    gtest_main
    Hash
    Sasl
    StringExtensions
    SystemAbstractions
)

add_test(
    NAME ${This}
    COMMAND ${This}
)
