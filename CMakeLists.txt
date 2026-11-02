cmake_minimum_required(VERSION 3.25)
project(WfpFtpGuard VERSION 0.1 LANGUAGES CXX)
if(NOT WIN32 OR NOT MSVC OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Use MSVC x64 on Windows with the Windows Driver Kit installed")
endif()
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
add_compile_definitions(UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
add_compile_options(/W4 /WX /permissive-)

set(WDK_ROOT "C:/Program Files (x86)/Windows Kits/10" CACHE PATH "WDK root")
set(WDK_VERSION "10.0.26100.0" CACHE STRING "Installed WDK version")
set(wdk_include "${WDK_ROOT}/Include/${WDK_VERSION}")
set(wdk_lib "${WDK_ROOT}/Lib/${WDK_VERSION}/km/x64")
if(NOT EXISTS "${wdk_include}/km/fwpsk.h")
    message(FATAL_ERROR "WDK kernel headers missing at ${wdk_include}")
endif()
get_filename_component(msvc_bin "${CMAKE_CXX_COMPILER}" DIRECTORY)
get_filename_component(msvc_host "${msvc_bin}" DIRECTORY)
get_filename_component(msvc_tools "${msvc_host}" DIRECTORY)
get_filename_component(msvc_root "${msvc_tools}" DIRECTORY)
set(driver_dir "${CMAKE_CURRENT_BINARY_DIR}/driver")
file(MAKE_DIRECTORY "${driver_dir}")
add_custom_command(OUTPUT "${driver_dir}/WfpFtpGuard.sys"
    COMMAND "${CMAKE_CXX_COMPILER}" /nologo /c /kernel /std:c++17 /Zl /GR- /EHs-c- /GS /W4 /WX /O1 /Z7
        /D_AMD64_ /D_WIN64 /DWIN64 /DNDIS_WDM=1 /DNDIS630=1
        /D_WIN32_WINNT=0x0A00 /DNTDDI_VERSION=0x0A00000C
        "/I${wdk_include}/km" "/I${wdk_include}/shared" "/I${wdk_include}/km/crt"
        "/I${msvc_root}/include" "/I${CMAKE_CURRENT_SOURCE_DIR}/common"
        "/Fo${driver_dir}/driver.obj" "${CMAKE_CURRENT_SOURCE_DIR}/driver/driver.cpp"
    COMMAND "${msvc_bin}/link.exe" /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:GsDriverEntry /NODEFAULTLIB /MACHINE:X64
        /INTEGRITYCHECK /OPT:REF /OPT:ICF /DEBUG "/PDB:${driver_dir}/WfpFtpGuard.pdb"
        "/OUT:${driver_dir}/WfpFtpGuard.sys" "${driver_dir}/driver.obj"
        "${wdk_lib}/ntoskrnl.lib" "${wdk_lib}/hal.lib" "${wdk_lib}/fwpkclnt.lib"
        "${wdk_lib}/ndis.lib" "${wdk_lib}/wdmsec.lib"
        "${wdk_lib}/BufferOverflowFastFailK.lib"
    DEPENDS driver/driver.cpp common/protocol.hpp common/ids.hpp common/ftp_probe.hpp
    VERBATIM)
add_custom_target(ftp-driver ALL DEPENDS "${driver_dir}/WfpFtpGuard.sys")

add_library(file-scanner STATIC console/file_scanner.cpp)
target_include_directories(file-scanner PUBLIC common console)
add_executable(ftp-guard console/main.cpp console/net_driver_session.cpp console/etw_monitor.cpp)
target_link_libraries(ftp-guard PRIVATE file-scanner fwpuclnt advapi32 ws2_32 tdh)
add_executable(ftp-traffic tests/traffic.cpp)
target_link_libraries(ftp-traffic PRIVATE ws2_32 wininet)
add_executable(guard-tests tests/unit.cpp)
target_link_libraries(guard-tests PRIVATE file-scanner)
enable_testing()
add_test(NAME guard-unit COMMAND guard-tests)
add_custom_target(sign-driver
    COMMAND powershell.exe -NoProfile -ExecutionPolicy Bypass -File "${CMAKE_CURRENT_SOURCE_DIR}/tools/Sign-Driver.ps1"
        -DriverPath "${driver_dir}/WfpFtpGuard.sys" -CertificatePath "${driver_dir}/WfpFtpGuard-Test.cer"
        -SignTool "${WDK_ROOT}/bin/${WDK_VERSION}/x64/signtool.exe"
    DEPENDS ftp-driver VERBATIM)
