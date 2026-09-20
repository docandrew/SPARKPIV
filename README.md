# SPARKPIV

A SPARK client for the PIV smart-card applet (NIST SP 800-73-4), the applet a
YubiKey exposes for X.509 identities. It lets a program use a key that lives
in a token: read the slot's certificate, verify the PIN, and have the token
sign. The program never holds the private key.

## What it does

`PIV` (`src/piv.ads`) speaks the applet protocol over a `Transmit` callback the
caller supplies, so it has no idea what the transport is:

- `Select_Applet`, `Verify_PIN`, `Read_Certificate` (the slot's certificate,
  DER, from the 70 tag of the certificate object), `Sign` (GENERAL
  AUTHENTICATE on a digest; ECDSA signatures come back DER-encoded, which is
  the TLS wire form).
- BER-TLV parsing, GET RESPONSE collection for long responses (SW1 = 61) and
  command chaining (CLA 10) for long commands, status-word mapping (wrong
  PIN with retries left, blocked, security status, not found).
- Dependencies: `Interfaces`. No allocation, no runtime, no C.

Not yet: provisioning (GENERATE ASYMMETRIC KEY PAIR, certificate import,
management-key authentication). `yubico-piv-tool` does that for now.

## Transports

The callback shape is `procedure (Cmd : in Bytes; Resp : out Bytes; Resp_Len :
out Index; OK : out Boolean)`, one complete APDU per call.

- `PIV.Linux_USB` (`src-linux/`, built by the optional `sparkpiv_linux.gpr`):
  plain Ada, Linux, not SPARK. Finds the token through sysfs, claims its CCID
  interface through `/dev/bus/usb` (usbfs ioctls; libc `open`/`ioctl`/`close`
  are the only foreign calls), and speaks USB CCID rev 1.1
  (`PC_to_RDR_XfrBlock` / `RDR_to_PC_DataBlock`). No pcscd, no libpcsclite,
  no libusb. It is the desktop stand-in for a native CCID driver on CuBit.
  Consumers `with "sparkpiv_linux.gpr"` (which brings `sparkpiv.gpr` along)
  and `with PIV.Linux_USB;`. The core `sparkpiv.gpr` stays OS-free.
- Anything else that moves APDUs: PC/SC, a serial reader, NFC.

## Probe

`examples/piv_probe` (`examples/examples.gpr`) lists what each slot holds
without a PIN and, given a directory, writes each certificate as DER so
`openssl x509 -inform der -in 9e.der -text` shows the key type. It depends on
nothing but this crate.

    alr exec -- gprbuild -P examples/examples.gpr && examples/bin/piv_probe /tmp

## See also

A TLS server whose identity key lives in a YubiKey slot, built on this crate,
is in the SPARKTLS repository under `examples/` (`tls_yubikey_server` and the
`piv_signer` callback that maps a TLS signature scheme to a PIV slot).

## Tests

`tests/test_piv_mock.adb` runs the client against a scripted transport with no
hardware: checks the exact APDUs emitted, status-word handling, TLV
extraction across GET RESPONSE chunk boundaries, and command chaining on a
512-byte RSA block.

    alr build
    alr exec -- gprbuild -P tests/tests.gpr && tests/bin/test_piv_mock

## Status and what "proven" means here

First cut, 2026-09-20. Builds with GNAT 16.

`src/` (the PIV protocol) is `SPARK_Mode On` and gnatprove discharges every
check at level 1 (205 checks, 0 unproved): absence of runtime errors on any
input the token or the caller can supply, including malformed TLV and bogus
lengths from a hostile card, and flow correctness. The contracts are
Silver-level (buffer bounds, "no output unless success"); they do not state
functional correctness of the protocol. That the APDUs are the right bytes
and the TLV walker follows BER is established by `tests/test_piv_mock.adb`
and by a real token, not by proof.

Verified against a YubiKey 5 (firmware 5.4.3) over `PIV.Linux_USB`: SELECT,
GET DATA with GET RESPONSE chaining (a 410-byte certificate), and GENERAL
AUTHENTICATE with a P-256 key in slot 9E signing live TLS 1.3 and TLS 1.2
handshakes. Command chaining (CLA 10, for RSA-sized payloads) and Ed25519
(algorithm E0, firmware 5.7+) have run only against the scripted transport.

Not SPARK: `src-linux/` (the Linux transport) and `examples/`.

Planned next:

- Split the transport: a SPARK `PIV.CCID` package for CCID message framing
  and response parsing (the part that consumes bytes from the device) over a
  two-call bulk-transfer interface, leaving only the usbfs and sysfs calls in
  the Linux shim. A different host (CuBit, via IPC to a USB service)
  implements the two bulk calls and gets PIV and CCID verified.
- Make the PIN scrub in `Verify_PIN` a real sanitize (flow analysis flags the
  final zeroing as a dead store the compiler may drop; SPARKNaCl's
  `No_Inline` idiom is the fix).
