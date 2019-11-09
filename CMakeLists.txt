# CMakeLists.txt for Sasl
#
# © 2019 by Richard Walters

cmake_minimum_required(VERSION 3.8)
set(This Sasl)

set(Headers
    include/Sasl/Client/Mechanism.hpp
    include/Sasl/Client/Plain.hpp
    include/Sasl/Client/Login.hpp
    include/Sasl/Client/Scram.hpp
)

set(Sources
    src/Client/Plain.cpp
    src/Client/Login.cpp
    src/Client/Scram.cpp
)

add_library(${This} STATIC ${Sources} ${Headers})
set_target_properties(${This} PROPERTIES
    FOLDER Libraries
)

target_include_directories(${This} PUBLIC include)

target_link_libraries(${This} PUBLIC
    Base64
    Hash
    StringExtensions
    SystemAbstractions
)

add_subdirectory(test)
