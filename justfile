clean:
    rm -rf build

build:
    cmake -S . -B build
    cmake --build build

run-client message: build
    ./build/client {{ message }}

run-server: build
    ./build/server
