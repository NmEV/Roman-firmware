# Build time guard for the Roman flash layout.
#
# storage.c puts the encrypted record at STORAGE_FLASH_OFFSET (1 MB) into flash,
# and the SDK links the program from flash offset 0. If the image ever grew into
# the store, the first POST /write would erase its own code - so fail the build
# instead.
#
# Invoked as: cmake -DIMAGE=<path to .bin> -DLIMIT=<bytes> -P check_size.cmake

if(NOT DEFINED IMAGE OR NOT DEFINED LIMIT)
    message(FATAL_ERROR "check_size: IMAGE and LIMIT must both be defined")
endif()

if(NOT EXISTS "${IMAGE}")
    message(FATAL_ERROR "check_size: '${IMAGE}' does not exist")
endif()

file(SIZE "${IMAGE}" IMAGE_SIZE)

if(IMAGE_SIZE GREATER LIMIT)
    message(FATAL_ERROR
        "check_size: ${IMAGE} is ${IMAGE_SIZE} bytes, which reaches into the flash "
        "region reserved for the Roman store (limit ${LIMIT}). Raise "
        "STORAGE_FLASH_OFFSET in storage.c (and LIMIT here) or shrink the image.")
endif()

math(EXPR HEADROOM "${LIMIT} - ${IMAGE_SIZE}")
message(STATUS "check_size: image ${IMAGE_SIZE} bytes, ${HEADROOM} bytes below the store")
