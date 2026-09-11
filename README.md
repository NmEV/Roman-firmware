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
| `pk` does not belong to `sk` | `400 {"error":"pk does not match sk"}` |
| body larger than 1024 bytes | `413` |
| flash erase/program failed | `500` |

The key pair is proven **before** it is committed: Roman signs a probe message
with the supplied `sk` and verifies it with the supplied `pk`. TweetNaCl itself
never cross-checks the two halves, and since provisioning happens only once, a
mismatched pair would otherwise leave the board signing with a key nobody can
verify.

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
