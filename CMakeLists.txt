cmake_minimum_required(VERSION 3.20)
project(peninsula_client VERSION 1.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets Network)

qt_standard_project_setup()

add_executable(peninsula_client
    main.cpp
    MainWindow.h
    MainWindow.cpp
)

target_link_libraries(peninsula_client PRIVATE Qt6::Widgets Qt6::Network)
