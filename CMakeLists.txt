cmake_minimum_required(VERSION 3.20)
project(msgtap VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" ARCH_LOWER)

if(ARCH_LOWER MATCHES "x86_64")
    set(BPF_ARCH x86)
elseif(ARCH_LOWER MATCHES "aarch64")
    set(BPF_ARCH arm64)
elseif(ARCH_LOWER MATCHES "arm")
    set(BPF_ARCH arm)
elseif(ARCH_LOWER MATCHES "mips")
    set(BPF_ARCH mips)
else()
    message(FATAL_ERROR "Unsupported architecture for BPF: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

set(BPF_PROG
	${CMAKE_CURRENT_LIST_DIR}/src/bpf/msgtap.bpf.c
)

set(BPF_OBJ
	${CMAKE_CURRENT_BINARY_DIR}/msgtap.bpf.o
)

set(BPF_SKEL
	${CMAKE_CURRENT_BINARY_DIR}/msgtap.skel.h
)

set(INCLUDE_DIR
	${CMAKE_CURRENT_BINARY_DIR}/src
)

set(USER_SRC
	${CMAKE_CURRENT_LIST_DIR}/src/user/ebpfmanager.cpp
	${CMAKE_CURRENT_LIST_DIR}/src/user/ebpfmanager.h
	${CMAKE_CURRENT_LIST_DIR}/src/user/msgtap.cpp
	${CMAKE_CURRENT_LIST_DIR}/src/user/uniquefd.h
)

add_custom_target(bpf_build
    COMMAND clang -g -O2 -target bpf -D__TARGET_ARCH_${BPF_ARCH}
    -c -o ${BPF_OBJ} ${BPF_PROG} -I${CMAKE_CURRENT_LIST_DIR}/src
    COMMAND bpftool gen skeleton ${BPF_OBJ} > ${BPF_SKEL}
    BYPRODUCTS ${BPF_OBJ} ${BPF_SKEL}
    DEPENDS ${BPF_PROG}
    COMMENT "Building BPF object and skeleton"
)

add_executable(msgtap ${USER_SRC} ${BPF_SKEL})
add_dependencies(msgtap bpf_build)

target_include_directories(msgtap PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/src
)

target_link_libraries(msgtap PRIVATE bpf)
