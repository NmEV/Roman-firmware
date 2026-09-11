// Roman's HTTP service: the USBNet signing endpoints plus one shot
// provisioning.
//
// Routes:
//   GET  /        endpoint index
//   GET  /health  liveness probe
//   GET  /info    device / firmware / engine / stored device id
//   GET  /sign    describes the POST /sign fields
//   POST /sign    Ed25519 signature made with the key stored in flash
//   POST /write   one shot provisioning (403 once writen is set)
//   POST /debug   diagnostics + maintenance, only while DEBUG_AVAILABLE is 1
//
// Nothing runs on its own thread: the server is driven by the main loop
// through usb_network_update().

#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <stdbool.h>

// Compile-time switch for POST /debug. Set to 0 to remove the endpoint, its
// handler, its request counters and its buffers from the image entirely.
//
// WARNING: /debug is unauthenticated and its "clear" action erases the stored
// keys, which is also the only recovery path when provisioning went wrong, so
// keep it available on the bench and disable it for anything shipped.
#ifndef DEBUG_AVAILABLE
#define DEBUG_AVAILABLE 1
#endif

// Creates the listening TCP socket on port 80. Returns false when it could not
// be created or bound.
bool http_server_init(void);
void http_server_deinit(void);

#endif // HTTP_SERVER_H
