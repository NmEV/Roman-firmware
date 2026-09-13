// The firmware version, in exactly one place.
//
// CMakeLists.txt sets ROMAN_VERSION and hands it to the SDK's
// pico_set_program_version(), which
//   * defines PICO_PROGRAM_VERSION_STRING for every source of the target, and
//   * embeds it as binary info, so picotool shows the same string.
// Bump ROMAN_VERSION there on every firmware change - this header only forwards
// it, and fails the build when a build system forgot to set it.

#ifndef ROMAN_VERSION_H
#define ROMAN_VERSION_H

#ifndef PICO_PROGRAM_VERSION_STRING
#error "PICO_PROGRAM_VERSION_STRING is not defined - set ROMAN_VERSION in CMakeLists.txt (pico_set_program_version)"
#endif

#define ROMAN_VERSION PICO_PROGRAM_VERSION_STRING

#endif // ROMAN_VERSION_H
