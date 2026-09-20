# SPARKPIV

A SPARK client for the PIV smart-card applet (NIST SP 800-73-4), the applet a
YubiKey exposes for X.509 identities. It lets a program use a key that lives
in a token: read the slot's certificate, verify the PIN, and have the token
sign. The program never holds the private key.

## What it does

`PIV` (`src/piv.ads`) speaks the applet protocol over a `Transmit` callback the
caller supplies, so it has no idea what the transport is:

- `Select_Applet`, `Verify_PIN`, `Read_Certificate` (the slot's certificate,
  DER, from the 70 tag of the certificate object; a certificate stored
  gzip-compressed is reported as `Unsupported_Encoding`, not handed up as
  DER), `Sign` (GENERAL AUTHENTICATE; ECDSA signatures come back
  DER-encoded, which is the TLS wire form). Slot PIN policy is the card's:
  9E none, 9A once per session, 9C (default) before every signature.
- BER-TLV parsing, GET RESPONSE collection for long responses (SW1 = 61;
  bounded, and a card that promises data without delivering is malformed),
  command chaining (CLA 10) for long commands, status-word mapping (wrong
  PIN with retries left, blocked, security status, not found).
- Dependencies: `Interfaces`. No allocation, no runtime, no C.

Not yet: provisioning (GENERATE ASYMMETRIC KEY PAIR, certificate import,
management-key authentication). `yubico-piv-tool` does that for now.

## Transports

`PIV` speaks to the card through one callback, `procedure (Cmd : in Bytes;
Resp : out Bytes; Resp_Len : out Index; OK : out Boolean)`, one complete APDU
per call. Below that sits a second SPARK layer for the common case of a USB
smart-card interface:

- `PIV.CCID` (`src/`, SPARK): USB CCID rev 1.1 message framing.
  `PC_to_RDR_IccPowerOn`, `PC_to_RDR_XfrBlock`, `RDR_to_PC_DataBlock`;
  message-type and sequence checks (a stale block from an earlier,
  timed-out command is discarded so the pipe resynchronises), a bounded
  time-extension budget, command status, length checks on what the device
  claims. It owns no I/O: a `Reader` carries two
  callbacks, `Bulk_Out (Data)` and `Bulk_In (Data, Len)`, and that is the
  whole OS-specific surface. `tests/test_ccid_mock.adb` drives it with a
  scripted reader.

- `PIV.Linux_USB` (`src-linux/`, built by the optional `sparkpiv_linux.gpr`):
  plain Ada, Linux, not SPARK. Finds the token through sysfs, claims its CCID
  interface through `/dev/bus/usb`, and implements the two bulk-transfer
  callbacks with usbfs ioctls (libc `open`/`ioctl`/`close` are the only
  foreign calls). No pcscd, no libpcsclite, no libusb. Consumers `with
  "sparkpiv_linux.gpr"` (which brings `sparkpiv.gpr` along) and `with
  PIV.Linux_USB;`. Another host (CuBit, via IPC to its USB service) supplies
  the same two callbacks and reuses `PIV` and `PIV.CCID` unchanged.
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
    alr exec -- gprbuild -P tests/tests.gpr && tests/bin/test_piv_mock && tests/bin/test_ccid_mock
    #  proof (the crate lists two project files, so name the one to prove):
    alr exec -- gnatprove -P sparkpiv.gpr --level=1

## Status and what "proven" means here

First cut, 2026-09-20. Builds with GNAT 16.

`src/` (the PIV protocol and the CCID framing) is `SPARK_Mode On` and
gnatprove discharges every check at level 1 (254 checks, 0 unproved):
absence of runtime errors on any input the token or the caller can supply,
including malformed TLV, bogus lengths and oversized CCID length claims from
a hostile device, and flow correctness. The contracts are
Silver-level (buffer bounds, "no output unless success"); they do not state
functional correctness of the protocol. That the APDUs are the right bytes
and the TLV walker follows BER is established by `tests/test_piv_mock.adb`
and by a real token, not by proof.

Verified against a YubiKey 5 (firmware 5.4.3) over `PIV.Linux_USB`: SELECT,
GET DATA with GET RESPONSE chaining (a 410-byte certificate), and GENERAL
AUTHENTICATE with a P-256 key in slot 9E signing live TLS 1.3 and TLS 1.2
handshakes. Command chaining (CLA 10, for RSA-sized payloads) and Ed25519
(algorithm E0, firmware 5.7+) have run only against the scripted transport.

Not SPARK: `src-linux/` (sysfs discovery and the two usbfs bulk calls) and
`examples/`.

Every user-space copy of the PIN (`Verify_PIN`'s padded buffer, the APDU
buffer in `PIV.Exchange`, the CCID message buffer, and the two copies in the
Linux shim) is zeroed on every exit with `pragma Inspection_Point`, which
keeps the store from being optimised away. The kernel's URB copy is outside
this program's reach.
