cmake_minimum_required(VERSION 3.10)
project(SimpleSSHServer C)

set(CMAKE_C_STANDARD 11)

# 添加 libssh 库
find_package(libssh REQUIRED)
include_directories(${LIBSSH_INCLUDE_DIRS})

# 生成可执行文件
add_executable(ssh_server src/main.c)

# 链接 libssh
target_link_libraries(ssh_server ${LIBSSH_LIBRARIES})
