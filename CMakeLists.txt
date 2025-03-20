cmake_minimum_required(VERSION 3.10)
project(BenignMalwareSample C)

# Specify the C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Enable extra warnings (recommended for educational purposes)
if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -pedantic)
endif()

# Create the executable from the main.c source file.
add_executable(benign_sample main.c)
