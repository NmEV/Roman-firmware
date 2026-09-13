// Roman: the USBNet signing service with one shot provisioning.
//
// Boot path is the same as the sign firmware (build-pico2-http-firmware): bring
// up the USB network interface, the DHCP server, mDNS and the HTTP service, then
// service everything from the main loop. 's' over UART shuts down cleanly.
//
// Two entry points on purpose: main() is naked and relocates the stack into SRAM
// before any C code runs on it (see stack.h), everything else is app_main().

#include <hardware/uart.h>
#include <hardware/watchdog.h>
#include <lwip/apps/mdns.h>
#include <lwip/ip.h>
#include <pico/stdlib.h>
#include <stdio.h>

#include "dhcpserver/dhcpserver.h"
#include "diag.h"
#include "http_server.h"
#include "led.h"
#include "stack.h"
#include "usb_network.h"
#include "version.h"

// usb network addresses
static const ip4_addr_t ownip = IPADDR4_INIT_BYTES(192, 168, 7, 1);
static const ip4_addr_t netmask = IPADDR4_INIT_BYTES(255, 255, 255, 0);
static const ip4_addr_t gateway = IPADDR4_INIT_BYTES(0, 0, 0, 0);

// The real entry point, entered by a tail branch from the naked main() below.
int app_main(void);

__attribute__((naked, noreturn)) int main(void) {
  __asm volatile(
      // MSPLIM first: with MSP still near the top of SCRATCH_Y the invariant
      // MSPLIM <= MSP holds at every point, while the other order would make an
      // exception entry in between illegal (Armv8-M).
      "ldr r0, =stack_ram\n"
      "msr msplim, r0\n"
      // stack_ram is 16 KB long - stack.c asserts the size - so the initial
      // stack pointer is the byte just past it. The 4 KB SCRATCH_Y stack that
      // PICO_STACK_SIZE reserves is then only used by the SDK boot code.
      "ldr r0, =stack_ram + 16384\n"
      "msr msp, r0\n"
      "isb\n"
      // Tail branch, not a call: no frame of ours keeps addressing the old
      // stack, it is simply left behind.
      "b app_main\n");
}

int app_main(void) {
  // Paint the unused part of the stack before anything deep runs: the lowest
  // byte the paint loses is how far the stack has reached, reported as
  // stack.used_max / stack.free_min by POST /debug.
  stack_init();

  stdio_uart_init();
  led_init();

  // The HTTP handlers run the deepest crypto chain in the firmware. If anything
  // in there ever stalls, this reboots the board instead of leaving it dead
  // until it is unplugged; watchdog_caused_reboot() is reported by POST /debug
  // and in the boot log. 3 s is far above the worst case flash erase (~0.4 s).
  watchdog_enable(3000, true); // true: keep running while a debugger has us halted
  // Capture how far the previous run got *before* clearing the marker: without
  // this, POST /debug could never report it (there is no UART on the bench).
  diag_capture_boot_stage();
  printf("roman: v%s boot (reset_by_watchdog=%d, last_stage=%s)\n",
         ROMAN_VERSION, watchdog_caused_reboot() ? 1 : 0,
         diag_stage_name(diag_boot_stage()));
  printf("roman: stack %u bytes in SRAM\n", (unsigned)stack_total());

  // setup USB network
  if (!usb_network_init(&ownip, &netmask, &gateway, true)) {
    printf("failed to start usb network\n");
    return -1;
  }

  // setup DHCP server
  dhcp_server_t dhcp_server;
  dhcp_server_init(&dhcp_server, (ip_addr_t *)&ownip, (ip_addr_t *)&netmask, false);

  // enable mDNS
  mdns_resp_init();
  mdns_resp_add_netif(netif_default, "roman");

  // start HTTP API server (it also reports the provisioning state)
  if (!http_server_init()) {
    printf("failed to start http server\n");
  }
  led_set_ready();

  // enter main loop
  printf("setup complete, entering main loop\n");
  int key = 0;
  uint32_t stack_tick = 0;
  while ((key != 's') && (key != 'S')) {
    usb_network_update();
    led_tick();
    // The paint is the recording: a deep call leaves its mark there and nothing
    // erases it, so the scan frequency does not affect what is reported - it is
    // only kept out of the hot path because scanning 16 KB costs a few hundred
    // microseconds. POST /debug samples on demand as well.
    if ((++stack_tick & 0xFFu) == 0u) {
      stack_check();
    }
    watchdog_update();
    key = getchar_timeout_us(0); // get any pending key press but don't wait
  }

  printf("shutting down\n");
  http_server_deinit();
  mdns_resp_remove_netif(netif_default);
  dhcp_server_deinit(&dhcp_server);
  usb_network_deinit();

  // app_main() was entered by a tail branch from the naked main(), so this
  // returns to the crt0 that called main() - still on the SRAM stack.
  return 0;
}
