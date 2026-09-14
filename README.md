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
| POST | `/write` | **one-shot provisioning** (403 once `writen` is set); the reply carries the generated X25519 public key |
| POST | `/clear` | erases the record for a caller that presents the provisioning Ed25519 secret key |
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

The reply carries the public half of the key pair that was just generated, so the
client learns which key the payload is boxed to:

```json
{"status":"ok","writen":true,"x25519_pk":"<base64 32B>"}
```

The X25519 **secret** key never leaves the board - it is stored next to the
ciphertext (see the security model). Erasing the record does not use it either:
`POST /clear` authenticates with the Ed25519 secret key **you** provisioned with,
which the board only ever saw once.

| Situation | Answer |
|---|---|
| already provisioned | `403 {"error":"already provisioned","writen":true}` |
| malformed base64, wrong length, bad device id | `400 {"error":"invalid pk/sk/device_id"}` |
| 64 byte `sk` whose embedded public key is not `pk` | `400 {"error":"pk does not match sk"}` |
| body larger than 1024 bytes | `413` |
| flash erase/program failed | `500` |

The only check the board performs is the cheap structural one: when `sk` is sent
as a full 64 byte value, its embedded public key must equal `pk`. **The board
does not verify that `pk` is derived from the 32 byte seed** - deliberately so,
even though the `crypto_sign_open()` check would fit the 16 KB stack now: the
board should not endorse a key it was simply handed. Verify it from the client
instead, right after provisioning: take one signature from `POST /sign` and check
it with your own `pk`, exactly as in the
[acceptance test](#acceptance-test-on-hardware). If it fails,
`POST /debug {"action":"clear"}` puts the board back into the empty state and you
can provision again - no reflashing needed.

### POST /clear

Erases the stored record so the board can be provisioned again. It only serves a
caller that can present the Ed25519 secret key installed by `POST /write`:

```sh
curl -X POST http://192.168.7.1/clear -d '{"ed25519_sk":"<base64 32B or 64B>"}'
```

* `ed25519_sk` is the value that was sent as `sk` to `/write` (the 32 byte seed, or
  the full 64 byte seed plus public key). `sk` is accepted as a shorthand name.
* It is compared in constant time against the decrypted stored key, so it proves
  possession of the provisioning secret - it is not a device-wide password.
* The X25519 secret key is deliberately not accepted here: the board never gave it
  out, and it is not what authorises erasure.

| Situation | Answer |
|---|---|
| key matches | `200 {"status":"ok","writen":false}` - the board is empty and can be provisioned again |
| nothing stored | `200 {"status":"ok","writen":false,"note":"nothing stored"}` (idempotent) |
| missing key | `400 {"error":"Missing field: ed25519_sk"}` |
| malformed key | `400 {"error":"invalid ed25519_sk"}` |
| wrong key | `403 {"error":"ed25519_sk does not match"}` |
| body larger than 1024 bytes | `413` |
| flash erase failed | `500 {"error":"flash erase failed"}` |

If the stored record is corrupt (it no longer decrypts), no key can be checked
against it and `/clear` answers 403; recovery then needs a build with
`DEBUG_AVAILABLE 1` and `POST /debug {"action":"clear"}`, which erases without a
credential and is meant for the bench only.

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
| *(empty)*, `{}`, `{"action":"snapshot"}` | diagnostics snapshot (firmware version, system, network, request counters, storage, stack headroom, Roman block) |
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

Two paths run the deep crypto and carry extra instrumentation: `POST /write`
(boxing + the flash erase) and `POST /sign` (the single deepest tweetnacl chain
in the firmware).

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
  `boxing`, `erase`, `program`, `done` for provisioning, and
  `sign-enter`, `sign-key`, `sign-parse`, `sign-crypto`, `sign-reply`,
  `sign-done` for signing.
* **Boot log** (UART, 115200): the size of the stack the firmware runs on
  (16384), the SDK version, the reset cause, the entropy source and the storage
  state.
* **Panic output**: a stack guard violation (UsageFault) makes the SDK print
  `PANIC` plus a file and line on that same UART - the difference between a
  fault and a silent stall. A fault raised on *exception entry* cannot print at
  all (there is no room to push a frame): the board then goes quiet and the
  watchdog reboots it 3 s later. The `/sign` failure this firmware fixes looked
  exactly like that.
* **Stack headroom** (`POST /debug`): `stack.used_max` / `stack.free_min`
  report the deepest the stack has been and what is left. Read them after
  exercising the endpoints; they are the measurement behind the
  [Stack budget](#stack-budget) table.
* **404 logging**: every 404 prints the method and path that were actually parsed
  (`http: 404 GETT /infoe`), and a request line without a method or path prints
  its own line. A routing bug that would otherwise be a bare `404 not found` is
  therefore visible in the log; `web.not_found` in the snapshot counts them.

If a request **times out or drops the connection after ~3 s**, that is the
watchdog rebooting a board that crashed: read `reset_by_watchdog` and
`roman.last_stage` from `POST /debug`, which names the step the previous run
died in (`sign-crypto` = inside `crypto_sign`, `program` = inside the flash
write). Provisioning leaves the sector empty when it does not complete, so the
board can simply be provisioned again - `writen` is only set once the whole
record has been programmed.

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

Every push to `main` also republishes a fixed **`latest` release**: the tag is
force-moved to the pushed commit and the release is recreated from the fresh
artifact, so the download URL never changes:

```sh
https://github.com/<owner>/<repo>/releases/download/latest/roman.uf2
https://github.com/<owner>/<repo>/releases/download/latest/SHA256SUMS.txt
```

Each push overwrites those assets - the release notes carry the firmware
version and the commit - so older builds remain only as workflow artifacts.

**The firmware version lives in exactly one place**: `set(ROMAN_VERSION ...)` at
the top of `CMakeLists.txt`. It is handed to the SDK's
`pico_set_program_version()`, which defines `PICO_PROGRAM_VERSION_STRING` for the
code (`version.h` forwards it as `ROMAN_VERSION`, and fails the build if a build
system forgot it) and records the same string as binary info, so `picotool` shows
it too. `GET /info`, `GET /`, `POST /debug` and the boot log all report it.
**Bump `ROMAN_VERSION` with every firmware change**, so a flashed board can always
be identified.

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

`tools/stack_test.c` does the same for the stack watermark scan in `stack.c`,
which is what `stack.free_min` is computed from:

```sh
cd tools && gcc -std=c11 -Wall -Wextra -I.. stack_test.c ../stack.c -o stack_test && ./stack_test
```

`tools/verify_signature.py` is the end to end signature check: it asks the board
for a signature, verifies it against the stored `ed25519_pk` and prints the stack
headroom and the request counters in the same run. It implements Ed25519 itself
(RFC 8032, checked against the RFC test vectors before it judges anything) and
needs only the standard library - no openssl, no `cryptography`, no `pynacl`:

```sh
python tools/verify_signature.py --host 192.168.7.1
# verifier    : RFC 8032 test vectors pass
# host        : 192.168.7.1 (firmware 0.2, device_id dev-01)
# message     : b'probe:debug-tool:0:dev-01'
# signature   : VALID
# tamper check: rejected
# stack       : used_max 5056 / total 16384, free_min 11328
# counters    : sign_ok 1, sign_bad 0, reset_by_watchdog False, last_stage none
```

## Stack budget

The stack a request runs on is **not** the 4 KB the SDK reserves. The pico-sdk
places `.stack_dummy` in the 4 KB SCRATCH_Y region and pins `__StackTop` to the
top of it, so `PICO_STACK_SIZE` cannot grow past 0x1000 (an 8 KB setting fails to
link with `section '.stack_dummy' will not fit in region 'SCRATCH_Y'`). `main()`
is therefore **naked** and switches MSP to a 16 KB stack in SRAM before any C
code runs on it (`stack.c`); SCRATCH_Y is left to the SDK boot code. It lowers
MSPLIM first and only then moves MSP, because Armv8-M requires `MSPLIM <= MSP` at
every instant - the other order would make an exception entry in between illegal,
which is a lockup rather than a fault.

Measured with `arm-none-eabi-gcc -O3 -mcpu=cortex-m33 -fstack-usage`. The frames
are dominated by fixed size arrays, so the toolchain version does not change the
picture:

| Function | Frame |
|---|---|
| `crypto_scalarmult` (whole X25519 ladder, inline) | 2232 B |
| `crypto_sign_open` | 1920 B |
| `add` (**called from inside `scalarmult`'s 256 iteration loop**) | 1736 B |
| `crypto_sign` | 1488 B |
| `scalarbase` / `crypto_hash` / `crypto_hashblocks` | 528 / 352 / 376 B |

The peaks that matter, with the USB -> lwIP -> HTTP chain below them. That chain
is **~0.6 KB** - read from `stack.used_now` at snapshot time, i.e. after the
crypto frames have been popped - not the ~1 KB that was assumed before:

| Path | Peak chain | Verdict |
|---|---|---|
| `POST /sign`: `crypto_sign` -> `scalarbase` -> `scalarmult` -> `add` | **~4.4 KB** | did not fit 4 KB: the `add` frames stay live under `crypto_sign`'s own frame, the stack guard faulted on exception entry (no output at all) and the watchdog reset the board 3 s later |
| `/info`, `/debug`: `crypto_box_open` -> `beforenm` -> `crypto_scalarmult` | ~3.5-3.9 KB | fitted, with a few hundred bytes to spare - which is why `/info` worked while `/sign` died |
| `/write`: `crypto_box` + flash erase | ~3.5 KB | fitted |

With the 16 KB stack the worst chain above leaves about 11 KB, and the firmware
reports the real number instead of an estimate:

* `stack.total` - size of the stack in use (16384)
* `stack.used_now` - how deep the snapshot itself is
* `stack.used_max` - the deepest the stack has been since boot (paint watermark)
* `stack.free_min` - `total - used_max`: **the number to watch**

**Rule: after adding any deep call chain, exercise it and read `stack.free_min`
from `POST /debug` on hardware.** Getting it wrong does not produce a nice panic:
a stack guard violation raised while pushing the exception frame cannot report
anything, so the board locks up silently, drops the connection and is rebooted by
the 3 s watchdog (`reset_by_watchdog: true`, `roman.last_stage` naming the step).

The watermark is exact unless the deepest bytes written happen to equal the paint
value (0xC5): those read as untouched and under-report usage by a few bytes. If an
interrupt lands while `stack_init()` paints, the report is a few bytes too high
instead. `tools/stack_test.c` covers the scan, including both directions.

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
# stored a key pair that matches the pk you sent (the board itself does not).
# tools/verify_signature.py does that and reports the stack headroom too:
python tools/verify_signature.py --host 192.168.7.1
#   verifier    : RFC 8032 test vectors pass
#   signature   : VALID
#   stack       : used_max 5056 / total 16384, free_min 11328
# or by hand, if you have openssl:
#   echo -n "c:x:1:dev-01" > msg.bin
#   echo "<signature>" | base64 -d > sig.bin
#   openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in msg.bin -sigfile sig.bin
curl -X POST http://192.168.7.1/debug -d '{"action":"snapshot"}'
#   (POST only: GET /debug is a 404 by design, like GET /write)
#   stack.total     16384
#   stack.used_max  5056 after the /sign above (the deep chain leaves a mark);
#                   it was 3480 before, i.e. the signing chain is the deepest
#   stack.free_min  11328  <- the headroom, see Stack budget
# /sign must not kill the connection: repeat it and watch reset_by_watchdog
for i in 1 2 3 4 5; do
  curl -s -X POST http://192.168.7.1/sign \
       -d '{"challenge":"c","context":"x","timestamp":"1"}'; echo
done
curl -X POST http://192.168.7.1/debug -d '{"action":"snapshot"}'   # sign_ok 6, reset_by_watchdog false
# power cycle the board, then:
curl http://192.168.7.1/info                        # still provisioned (persistence)
curl -X POST http://192.168.7.1/debug               # snapshot, roman.writen = true
# POST /clear authenticates with the Ed25519 secret key you provisioned with:
curl -X POST http://192.168.7.1/clear -d '{"ed25519_sk":"<b64>"}'        # 200, writen false
curl -X POST http://192.168.7.1/clear -d '{"ed25519_sk":"<wrong>"}'      # 403
curl -X POST http://192.168.7.1/clear -d '{"ed25519_sk":"not base64!"}'  # 400
curl http://192.168.7.1/info                        # storage empty again
curl -X POST http://192.168.7.1/write \
     -d '{"pk":"<b64>","sk":"<b64>","device_id":"dev-09"}'      # 200, provisioned again
# bench only (DEBUG_AVAILABLE 1), erases without a credential:
curl -X POST http://192.168.7.1/debug -d '{"action":"clear"}'
```

## Credits

USB Ethernet, lwIP bring-up, the DHCP server and the HTTP connection machinery
come from [USBNet](https://github.com/mattmyne/usbnet) by Matthew Bennett (MIT).
Cryptography is[TweetNaCl](https://tweetnacl.cr.yp.to/) (public domain). See `LICENSE`.
