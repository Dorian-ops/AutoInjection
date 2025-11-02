cmake_minimum_required(VERSION 3.31)
project(STALCRAFTXDorianClient)

set(CMAKE_CXX_STANDARD 20)

add_executable(STALCRAFTXDorianClient main.cpp
        dllmain.cpp
        dllmain.h
        handles/dllAutoAim.cpp
        handles/dllAutoAim.h)
