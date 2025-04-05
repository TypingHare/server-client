cmake_minimum_required(VERSION 3.30)
project(client_server)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_EXTENSIONS ON)

include_directories("/opt/homebrew/include")

add_executable(client
        src/main.c
        src/common.h
        src/common.c
        src/client.h
        src/client.c
)
target_link_libraries(client
        /opt/homebrew/lib/libmbedtls.dylib
        /opt/homebrew/lib/libmbedx509.dylib
        /opt/homebrew/lib/libmbedcrypto.dylib
)
target_compile_definitions(client PRIVATE CLIENT)

add_executable(server
        src/main.c
        src/common.h
        src/common.c
        src/server.h
        src/server.c
)
target_link_libraries(server
        /opt/homebrew/lib/libmbedtls.dylib
        /opt/homebrew/lib/libmbedx509.dylib
        /opt/homebrew/lib/libmbedcrypto.dylib
)
target_compile_definitions(server PRIVATE SERVER)
