cmake_minimum_required(VERSION 3.14)

project(HoneyDew
  VERSION   1.0.0
  LANGUAGES C
  DESCRIPTION "多协议高交互蜜罐系统"
)

# ---------------------------------------------------------------------------
# C 标准
# ---------------------------------------------------------------------------
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# 编译选项（按构建类型区分）
# ---------------------------------------------------------------------------
add_compile_options(-Wall -Wextra -Wpedantic)

set(CMAKE_C_FLAGS_DEBUG   "-g -O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "构建类型 (Debug/Release)" FORCE)
endif()

message(STATUS "[蜜罐] 构建类型: ${CMAKE_BUILD_TYPE}")
message(STATUS "[蜜罐] C 编译器: ${CMAKE_C_COMPILER}")

# ---------------------------------------------------------------------------
# 平台检测
# ---------------------------------------------------------------------------
if(WIN32)
  add_definitions(-D_WIN32)
  set(PLATFORM_LIBS ws2_32)
else()
  find_package(Threads REQUIRED)
  set(PLATFORM_LIBS Threads::Threads)
endif()

# ---------------------------------------------------------------------------
# 依赖: libssh
# ---------------------------------------------------------------------------
find_package(PkgConfig QUIET)

if(PkgConfig_FOUND)
  pkg_check_modules(LIBSSH QUIET libssh)
endif()

if(NOT LIBSSH_FOUND)
  find_path(LIBSSH_INCLUDE_DIRS
    NAMES libssh/libssh.h
    PATHS
      /opt/homebrew/include
      /usr/local/include
      /usr/include
  )
  find_library(LIBSSH_LIBRARIES
    NAMES ssh
    PATHS
      /opt/homebrew/lib
      /usr/local/lib
      /usr/lib
  )

  if(LIBSSH_INCLUDE_DIRS AND LIBSSH_LIBRARIES)
    set(LIBSSH_FOUND TRUE)
    message(STATUS "[蜜罐] libssh 手动定位: ${LIBSSH_LIBRARIES}")
  else()
    message(FATAL_ERROR
      "[蜜罐] 未找到 libssh。\n"
      "  macOS:  brew install libssh\n"
      "  Ubuntu: sudo apt install libssh-dev\n"
      "  Fedora: sudo dnf install libssh-devel"
    )
  endif()
endif()

message(STATUS "[蜜罐] libssh 头文件: ${LIBSSH_INCLUDE_DIRS}")
message(STATUS "[蜜罐] libssh 库文件: ${LIBSSH_LIBRARIES}")

# ---------------------------------------------------------------------------
# 源文件
# ---------------------------------------------------------------------------
set(HONEYDEW_SOURCES
  main.c
  src/service/session.c
  src/service/finite_state.c
  src/service/dispatcher.c
  src/service/ssh_honeypot.c
  src/service/ftp_honeypot.c
  src/service/telnet_honeypot.c
  src/service/smtp_honeypot.c
  src/service/mysql_honeypot.c
  src/service/redis_honeypot.c
  src/service/postgresql_honeypot.c
  src/service/pop3_honeypot.c
  src/service/imap_honeypot.c
  src/service/dns_honeypot.c
  src/service/questdb_honeypot.c
  src/utilities/logger.c
  src/utilities/audit.c
)

set(HONEYDEW_HEADERS
  include/audit.h
  include/config.h
  include/connection.h
  include/dispatcher.h
  include/finite_state.h
  include/logger.h
  include/session.h
  include/state.h
)

# ---------------------------------------------------------------------------
# 目标: 蜜罐
# ---------------------------------------------------------------------------
add_executable(蜜罐 ${HONEYDEW_SOURCES} ${HONEYDEW_HEADERS})

target_include_directories(蜜罐 PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${LIBSSH_INCLUDE_DIRS}
)

target_link_libraries(蜜罐 PRIVATE
  ${LIBSSH_LIBRARIES}
  ${PLATFORM_LIBS}
)

# 设置输出目录（统一到 build 根目录）
set_target_properties(蜜罐 PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
  RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}
  RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}
)

# ---------------------------------------------------------------------------
# SSH 密钥自动生成
# ---------------------------------------------------------------------------
set(KEY_DIR  "${CMAKE_BINARY_DIR}/keys")
set(KEY_PRIV "${KEY_DIR}/ssh_host_rsa_key")
set(KEY_PUB  "${KEY_PRIV}.pub")

if(WIN32)
  add_custom_command(
    OUTPUT  ${KEY_PRIV} ${KEY_PUB}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${KEY_DIR}
    COMMAND ssh-keygen -t rsa -b 2048 -f ${KEY_PRIV} -N "" -q -C "honeydew"
    COMMENT "[密钥生成] 正在生成 RSA-2048 SSH 主机密钥 (Windows)..."
  )
else()
  add_custom_command(
    OUTPUT  ${KEY_PRIV} ${KEY_PUB}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${KEY_DIR}
    COMMAND chmod 700 ${KEY_DIR}
    COMMAND ssh-keygen -t rsa -b 2048 -f ${KEY_PRIV} -N "" -q -C "honeydew@蜜罐"
    COMMAND chmod 600 ${KEY_PRIV}
    COMMAND chmod 644 ${KEY_PUB}
    COMMENT "[密钥生成] 正在生成 RSA-2048 SSH 主机密钥..."
  )
endif()

add_custom_target(ssh_keys DEPENDS ${KEY_PRIV})
add_dependencies(蜜罐 ssh_keys)

# 构建后复制密钥到源码目录的 keys/（运行时需要）
add_custom_command(TARGET 蜜罐 POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_SOURCE_DIR}/keys
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${KEY_PRIV} ${CMAKE_SOURCE_DIR}/keys/
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${KEY_PUB}  ${CMAKE_SOURCE_DIR}/keys/
  COMMENT "[密钥部署] 复制密钥到 ${CMAKE_SOURCE_DIR}/keys/"
)

# ---------------------------------------------------------------------------
# 安装规则
# ---------------------------------------------------------------------------
include(GNUInstallDirs)

install(TARGETS 蜜罐
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(DIRECTORY ${KEY_DIR}/
  DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/honeydew/keys
  FILE_PERMISSIONS OWNER_READ OWNER_WRITE
  DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
)

install(FILES ${HONEYDEW_HEADERS}
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/honeydew
)

# ---------------------------------------------------------------------------
# 信息摘要
# ---------------------------------------------------------------------------
message(STATUS "")
message(STATUS "========================================")
message(STATUS "  HoneyDew v${PROJECT_VERSION}")
message(STATUS "  构建类型:   ${CMAKE_BUILD_TYPE}")
message(STATUS "  安装前缀:   ${CMAKE_INSTALL_PREFIX}")
message(STATUS "  密钥目录:   ${KEY_DIR}")
message(STATUS "========================================")
message(STATUS "")
