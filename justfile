clean:
    rm -rf build

build:
    cmake -S . -B build
    cmake --build build

run-client message: build
    ./build/client {{ message }}

run-server: build
    ./build/server

s_client:
    openssl s_client -connect localhost:4433