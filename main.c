// Roman: the USBNet signing service with one shot provisioning.
//
// Boot path is the same as the sign firmware (build-pico2-http-firmware): bring
// up the USB network interface, the DHCP server, mDNS and the HTTP service, then
// service everything from the main loop. 's' over UART shuts down cleanly.

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
#include "usb_network.h"

// usb network addresses
static const ip4_addr_t ownip = IPADDR4_INIT_BYTES(192, 168, 7, 1);
static const ip4_addr_t netmask = IPADDR4_INIT_BYTES(255, 255, 255, 0);
static const ip4_addr_t gateway = IPADDR4_INIT_BYTES(0, 0, 0, 0);

int main() {
  stdio_uart_init();
  led_init();

  // The HTTP handlers run the deepest crypto chain in the firmware. If anything
  // in there ever stalls, this reboots the board instead of leaving it dead
  // until it is unplugged; watchdog_caused_reboot() is reported by POST /debug
  // and in the boot log. 3 s is far above the worst case flash erase (~0.4 s).
  watchdog_enable(3000, true); // true: keep running while a debugger has us halted
  printf("roman: boot (reset_by_watchdog=%d, last_stage=%s)\n",
         watchdog_caused_reboot() ? 1 : 0, diag_stage_name(diag_previous_stage()));
  diag_stage(DIAG_STAGE_IDLE); // this boot starts clean

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
  while ((key != 's') && (key != 'S')) {
    usb_network_update();
    led_tick();
    watchdog_update();
    key = getchar_timeout_us(0); // get any pending key press but don't wait
  }

  printf("shutting down\n");
  http_server_deinit();
  mdns_resp_remove_netif(netif_default);
  dhcp_server_deinit(&dhcp_server);
  usb_network_deinit();

  return 0;
}
