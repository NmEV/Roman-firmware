# Generated Cmake Pico project file

cmake_minimum_required(VERSION 3.13)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Initialise pico_sdk from installed location
# (note this can come from environment, CMake cache etc)

# == DO NOT EDIT THE FOLLOWING LINES for the Raspberry Pi Pico VS Code Extension to work ==
if(WIN32)
    set(USERHOME $ENV{USERPROFILE})
else()
    set(USERHOME $ENV{HOME})
endif()
set(sdkVersion 2.2.0)
set(toolchainVersion 14_2_Rel1)
set(picotoolVersion 2.2.0)
set(picoVscode ${USERHOME}/.pico-sdk/cmake/pico-vscode.cmake)
if (EXISTS ${picoVscode})
    include(${picoVscode})
endif()
# ====================================================================================
set(PICO_BOARD pico2 CACHE STRING "Board type")

# Inject the project wide pico-sdk configuration (pico_config.h) into the SDK's
# generated pico/config_autogen.h: it raises PICO_STACK_SIZE, which the tweetnacl
# signing and boxing call chains need. Must be set before pico_sdk_init() so the
# generated config header picks it up.
set(PICO_CONFIG_HEADER_FILES "${CMAKE_CURRENT_SOURCE_DIR}/pico_config.h" CACHE STRING
    "extra headers included from pico/config.h")

# Pull in Raspberry Pi Pico SDK (must be before project)
include(pico_sdk_import.cmake)

project(roman C CXX ASM)

# Initialise the Raspberry Pi Pico SDK
pico_sdk_init()

# Add executable. Default name is the project name, version 0.1

add_executable(roman
    main.c
    http_server.c
    keystore.c
    record.c
    storage.c
    led.c
    usb_network.c
    usb_descriptors.c
    tweetnacl.c
    dhcpserver/dhcpserver.c
    ${PICO_TINYUSB_PATH}/lib/networking/rndis_reports.c
)

pico_set_program_name(roman "roman")
pico_set_program_version(roman "0.1")

# Modify the below lines to enable/disable output over UART/USB
pico_enable_stdio_uart(roman 1)
pico_enable_stdio_usb(roman 0)

# Add libraries to the build
target_link_libraries(roman
    pico_stdlib
    tinyusb_device
    pico_lwip
    pico_lwip_nosys
    pico_lwip_mdns
    pico_unique_id
    pico_flash
    pico_rand
    hardware_watchdog # POST /debug action=reset (http_server.c)
)

# Add include directories to the build
target_include_directories(roman PRIVATE
    ${PICO_TINYUSB_PATH}/lib/networking # for rndis_protocol.h
    ${CMAKE_CURRENT_LIST_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/.. # for our common lwipopts or any other standard includes, if required
)

pico_add_extra_outputs(roman)

# The encrypted store sits at STORAGE_FLASH_OFFSET (1 MB) into flash while the
# SDK links the image from offset 0, so the image must stay below that offset or
# the first write would erase part of the program. LIMIT is the offset minus one
# 4 KB sector; check_size.cmake fails the build if the .bin ever gets there.
add_custom_command(TARGET roman POST_BUILD
    COMMAND ${CMAKE_COMMAND}
            -DIMAGE=$<TARGET_FILE_DIR:roman>/roman.bin
            -DLIMIT=1044480
            -P ${CMAKE_CURRENT_LIST_DIR}/check_size.cmake
    VERBATIM
    COMMENT "Checking that the image stays clear of the encrypted store"
)
