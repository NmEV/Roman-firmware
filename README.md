# Roman

Roman is the USBNet **signing service with one-shot provisioning**: the three
endpoints of the sign firmware (`/health`, `/info`, `/sign`) now take their
Ed25519 key pair and their device id from an **encrypted flash store** instead of
compile-time constants, and they are installed once through `POST /write`.

It is built on the USB Ethernet (TinyUSB + lwIP) base of
[USBNet](https://github.com/NellowTC/USBNet) / the sign firmware, with the
encrypted storage construction of the `firmware-with-storage` firmware. See
[Credits](#credits).

## Endpoints

A small HTTP server runs on port 80 (IP `192.168.7.1`, also `roman.local`).

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | endpoint index |
| GET | `/health` | `{"status":"ok"}` |
| GET | `/info` | device / firmware / version / engine / stored device id / storage state |
| GET | `/sign` | describes the `POST /sign` fields |
| POST | `/sign` | Ed25519 signature made with the stored key |
| POST | `/write` | **one-shot provisioning** (403 once `writen` is set) |
| POST | `/debug` | diagnostics + maintenance (compile-time gated, see below) |
| OPTIONS | * | CORS preflight |

### POST /write - provisioning

```sh
curl -X POST http://192.168.7.1/write \
  -d '{"pk":"<base64 32B>","sk":"<base64 32B or 64B>","device_id":"dev-01"}'
```

* `pk` is the raw Ed25519 public key (32 bytes, base64).
* `sk` is either the 32-byte seed or the full 64-byte `seed || public key`.
* `device_id` must be 1..32 characters of `[A-Za-z0-9._-]` - it is embedded
  unescaped in the `/info` and `/sign` JSON replies.

What happens on success:

1. a fresh **X25519 key pair** and a fresh 24-byte nonce are generated;
2. the X25519 key pair is written to flash **in plaintext** (it is the bootstrap
   for reading the rest);
3. the Ed25519 key pair and the device id are boxed with it
   (`crypto_box`, X25519 + XSalsa20-Poly1305) and the **ciphertext** is written;
4. `writen` becomes true and every later `POST /write` answers **403**.

| Situation | Answer |
|---|---|
| already provisioned | `403 {"error":"already provisioned","writen":true}` |
| malformed base64, wrong length, bad device id | `400 {"error":"invalid pk/sk/device_id"}` |
| 64 byte `sk` whose embedded public key is not `pk` | `400 {"error":"pk does not match sk"}` |
| body larger than 1024 bytes | `413` |
| flash erase/program failed | `500` |

The only check the board performs is the cheap structural one: when `sk` is sent
as a full 64 byte value, its embedded public key must equal `pk`. **The board
does not verify that `pk` is derived from the 32 byte seed** - that check needs
`crypto_sign_open()`, which does not fit the 4 KB stack (see
[Stack budget](#stack-budget)). Verify it from the client instead, right after
provisioning: take one signature from `POST /sign` and check it with your own
`pk`, exactly as in the [acceptance test](#acceptance-test-on-hardware). If it
fails, `POST /debug {"action":"clear"}` puts the board back into the empty state
and you can provision again - no reflashing needed.

### POST /sign

```sh
curl -X POST http://192.168.7.1/sign \
  -d '{"challenge":"c","context":"x","timestamp":"1700000000"}'
```

The signed message is `challenge:context:timestamp:device_id`, the reply is
`{"signature":"<base64 64B>","timestamp":"...","device_id":"..."}`. The key is
read back (decrypted) from flash, so a power cycle does not disturb it. Before
provisioning the endpoint answers **503 not provisioned**.

### Generating a key pair

```sh
openssl genpkey -algorithm ED25519 -out key.pem
# 32-byte seed  -> sk
openssl pkey -in key.pem -outform DER | tail -c 32 | base64 -w0
# 32-byte public key -> pk
openssl pkey -in key.pem -pubout -outform DER | tail -c 32 | base64 -w0
```

Verifying a signature offline:

```sh
openssl pkeyutl -verify -pubin -inkey pub.pem -rawin \
  -in message.bin -sigfile signature.bin
```

### POST /debug (bench only)

Gated by `DEBUG_AVAILABLE` at the top of `http_server.h` (default 1). With it
set to 0 the route, its handler, its counters and its buffers are compiled out
and `POST /debug` falls through to 404.

| Body | Result |
|---|---|
| *(empty)*, `{}`, `{"action":"snapshot"}` | diagnostics snapshot (system, network, request counters, storage, Roman block) |
| `{"action":"clear"}` | erases the record: `writen` returns to 0 and the board can be provisioned again |
| `{"action":"reset"}` | reboots the board ~100 ms after the reply has been acknowledged |
| anything else | 400 |

> **Warning**: `/debug` is unauthenticated and `clear` wipes the provisioned
> keys. That is also the **only recovery path** when provisioning went wrong, so
> it is kept on the bench and should be compiled out (`DEBUG_AVAILABLE 0`) for
> anything shipped.

## Storage layout

The record lives at **1 MB into flash** (`STORAGE_FLASH_OFFSET` in
`storage.c`); one 4 KB sector is erased and 512 bytes are programmed.

```
page 0   0x000  4   magic "ROMN"
         0x004  4   plaintext payload length (uint32 LE)
         0x008  1   format version = 1
         0x00C  24  crypto_box nonce           (fresh per write)
         0x024  32  X25519 public key          (plaintext)
         0x044  32  X25519 secret key          (plaintext, by design)
page 1   0x100  16  Poly1305 MAC (section 0)
         0x110 232  ciphertext (section 0)
         0x1F8  4   "DONE" -> the stored writen flag, programmed LAST
```

The payload inside the box is `version | id length | Ed25519 pk(32) |
Ed25519 sk(64) | device_id`.

`writen` is the `"DONE"` marker at the **end** of the programmed region.
`flash_range_program()` walks ascending addresses, so the marker can only become
valid after everything before it has landed: losing power in the middle of
provisioning leaves `writen == 0` and the board can simply be provisioned again,
instead of being locked out with `writen == 1` and an unusable record.

`CMakeLists.txt` checks after every build that `roman.bin` still fits below the
store (`check_size.cmake`); if the image ever grew into it, the first write would
erase part of the program, so the build fails instead.

## Security model - read this before trusting it

* **What it gives**: the payload (Ed25519 key pair + device id) is never stored
  as plaintext, and a corrupt or tampered section is detected (Poly1305) instead
  of being silently used.
* **What it does not give**: confidentiality against anyone who can read flash.
  The X25519 **secret** key sits in the same sector as the ciphertext it opens -
  that is what makes the record self-contained across reboots - so a flash dump
  yields the Ed25519 private key. The construction hides the keys from casual
  inspection, it does not protect them.
* The HTTP endpoints have **no authentication**: anyone who can reach
  `192.168.7.1` over the USB link can read `/info`, ask for signatures, and (on
  a bench build) wipe the keys through `/debug`. Same trust model as the sign
  firmware this is derived from.
* `/sign` accepts any `challenge`/`context`/`timestamp` string; the timestamp is
  echoed back, not validated.

## Troubleshooting

Provisioning (`POST /write`) is the only path that runs the deep crypto chain
and the flash erase, so it carries extra instrumentation:

* **Hardware watchdog** (3 s, armed in `main.c`): if anything in a handler
  stalls, the board reboots itself instead of staying dead until it is unplugged.
  `POST /debug` then reports `reset_by_watchdog: true`.
* **Stage markers** (`diag.c`): every step of provisioning is written to a
  watchdog scratch register, which survives a watchdog reset but not a power
  cycle. The next boot logs `last_stage=...` and the snapshot carries
  `roman.last_stage`, so a hang is localised **without** a UART adapter. The
  value is captured into RAM at startup *before* the marker is cleared, so it
  survives until the snapshot is read. Stages:
  `write-received`, `fields-ok`, `pair-check`, `pair-ok`, `entropy`,
  `boxing`, `erase`, `program`, `done`.
* **Boot log** (UART, 115200): stack size, SDK version, reset cause, entropy
  source and storage state.
* **Panic output**: a stack guard violation (UsageFault) makes the SDK print
  `PANIC` plus a file and line on that same UART - the difference between a
  fault and a silent stall.

If `/write` times out: wait 3 s for the watchdog (or replug), read
`roman.last_stage`, and compare it with the boot log. Provisioning leaves the
sector empty when it does not complete, so the board can simply be provisioned
again - `writen` is only set once the whole record has been programmed.

## Entropy note

`randombytes()` deliberately does not use pico_rand's `get_rand_32()`: that
waits for the hardware TRNG with an unbounded `while (trng_hw->trng_busy);`
inside a spin lock with interrupts disabled, so a TRNG that never answered would
hang the firmware from inside a request. Roman drives the same peripheral with a
10 ms deadline and falls back to a splitmix64 generator seeded from the bootrom's
TRNG random (`rom_get_boot_random`, 128 bits per boot) plus the board id and the
microsecond timer. The primary path is still the live hardware TRNG; only if it
does not answer does the key material lose per-call fresh entropy - and since the
X25519 private key is stored next to the ciphertext anyway (see the security
model), that does not change the practical threat model.

## Build

VS Code with the Raspberry Pi Pico extension works as-is (the `.vscode` files
are carried over). From the command line:

```sh
cmake -S . -B build -G Ninja \
      -DPICO_BOARD=pico2 -DCMAKE_BUILD_TYPE=Release \
      -DPICO_SDK_PATH=/path/to/pico-sdk \
      -DPICO_TOOLCHAIN_PATH=/path/to/arm-none-eabi
cmake --build build
```

CI (`.github/workflows/main.yml`) builds the same way on Ubuntu and publishes
`roman.uf2` / `roman.elf` / `roman.bin` as the `roman-firmware` artifact.

UART stdio is enabled, USB stdio is not; sending `s` over UART shuts down
cleanly.

## Bench tool

`debug_tool.py` is the Tkinter console (adapted from the storage firmware):
`POST /debug` rendered as a tree with per-refresh deltas, a provisioning form
(`device_id` + `pk` + `sk`), a "试签一个" button and the log pane.

```sh
python debug_tool.py --host 192.168.7.1 --interval 2 --auto
```

`tools/record_test.c` unit tests the pure record codec and the strict base64
decoder on the host (no Pico SDK needed):

```sh
cd tools && gcc -std=c11 -Wall -Wextra -I.. record_test.c ../record.c -o record_test && ./record_test
```

## Stack budget

The core-0 stack is capped at 4 KB (the pico-sdk places `.stack_dummy` in the
4 KB SCRATCH_Y region; `PICO_STACK_SIZE` is already at that ceiling). TweetNaCl
frames are large, so the depth of each path matters. Measured with
`arm-none-eabi-gcc -O2 -mcpu=cortex-m33 -fstack-usage`:

| Function | Frame |
|---|---|
| `crypto_scalarmult_curve25519` | 1496 B |
| `crypto_sign_ed25519_tweet_open` | 1904 B |
| `add` (called by sign_open) | 1200 B |
| `crypto_sign_ed25519_tweet` | 1256 B |
| `crypto_hash_sha512` (+ hashblocks) | 352 + 392 B |
| `crypto_scalarmult` (field helper), `scalarbase`, `pack` | 32 / 528 / 432 B |

Resulting peaks, including roughly 1 KB of lwIP receive chain and handler frames:

| Path | Peak | Headroom |
|---|---|---|
| `POST /write` (crypto_box chain) | ~2.8-3.0 KB | ~1.1 KB |
| `POST /sign` (crypto_sign + hash) | ~3.0 KB | ~1.1 KB |
| `POST /debug` snapshot | ~1.2 KB | ~2.8 KB |
| `crypto_sign_open` path (probe check) | ~4.0-4.3 KB | **overflows** |

**Rule: never call `crypto_sign_open()` from this firmware.** Its own 1904 byte
frame plus `add()`'s 1200 bytes do not fit under the 4 KB ceiling together with
the network stack, and the failure mode is a silent lockup that only the watchdog
recovers (it was reported as `last_stage=pair-check` before the probe was
removed). Any change that introduces a deeper tweetnacl path has to be checked
against this table first.

## Acceptance test on hardware

```sh
curl http://192.168.7.1/health                      # {"status":"ok"}
curl http://192.168.7.1/info                        # id null, storage empty
curl -X POST http://192.168.7.1/sign -d '{"challenge":"c","context":"x","timestamp":"1"}'
                                                    # 503 not provisioned
curl -X POST http://192.168.7.1/write \
     -d '{"pk":"<b64>","sk":"<b64>","device_id":"dev-01"}'      # 200
curl http://192.168.7.1/info                        # id dev-01, storage provisioned
curl -X POST http://192.168.7.1/write \
     -d '{"pk":"<b64>","sk":"<b64>","device_id":"dev-02"}'      # 403
curl -X POST http://192.168.7.1/sign -d '{"challenge":"c","context":"x","timestamp":"1"}'
                                                    # 200 + signature
# Check that signature locally with your own pk: this is what proves the board
# stored a key pair that matches the pk you sent (the board itself does not):
#   echo -n "c:x:1:dev-01" > msg.bin
#   echo "<signature>" | base64 -d > sig.bin
#   openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in msg.bin -sigfile sig.bin
# power cycle the board, then:
curl http://192.168.7.1/info                        # still provisioned (persistence)
curl -X POST http://192.168.7.1/debug               # snapshot, roman.writen = true
curl -X POST http://192.168.7.1/debug -d '{"action":"clear"}'   # recovery path
```

## Credits

USB Ethernet, lwIP bring-up, the DHCP server and the HTTP connection machinery
come from [USBNet](https://github.com/NellowTC/USBNet) by Matthew Bennett (MIT),
via the `build-pico2-http-firmware` sign firmware; the encrypted flash store is
derived from the `firmware-with-storage` firmware. Cryptography is
[TweetNaCl](https://tweetnacl.cr.yp.to/) (public domain). See `LICENSE`.
