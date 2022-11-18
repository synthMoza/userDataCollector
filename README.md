# User Data Collector

User Data Collector is a study project in MIPT. It uses different approaches at encrypting data for protected exchange of data between the client and the server.



# Build & Compile
Project uses CMake for build a binary tree, so, to compile the project, type this inside the root directory (Unix example):
```
mkdir build
cd build
cmake <optional_variables> ..
```

Optional variables are passes to CMake to build unit/perfomance tests or to choose build type:
* ```-DWITH_TESTS=1``` - build program with unit tests
* ```-DWITH_TESTS=1 -DWITH_PERF_TESTS=1``` - build program with both unit and perfomance tests (you can't build perfomance tests without unit tests)
* ```-DCMAKE_BUILD_TYPE=Debug (Release)``` - choose build type for the program (different compilation flags will be used, including debug symbols for Debug build type)

Almost all libraries are presented in the repository and will be built except Boost due to its size. So, to compile this project, don't forget to install boost:
```
sudo apt install libboost-all-dev
```
# Implementation
TODO
# Encryption Algorithms
TODO
# Perfomance Tests
TODO
# Authors
[synthMoza](https://github.com/synthMoza)

[Greezzee](https://github.com/Greezzee)

[Vlad-creator](https://github.com/Vlad-creator)