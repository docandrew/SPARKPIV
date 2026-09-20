--  SPARKPIV: a client for the PIV smart-card applet (NIST SP 800-73-4),
--  the applet a YubiKey exposes for X.509 identities. Transport-agnostic:
--  every command goes through the Transmit callback the caller supplies
--  (PC/SC on a desktop, a native CCID/USB driver on CuBit). No dependency
--  beyond Interfaces, no allocation, no runtime.
--
--  Scope of this first cut: what a TLS identity needs. Select the applet,
--  verify the PIN, read a slot's certificate, sign a digest in a slot.
--  Provisioning (key generation, certificate import, management-key
--  authentication) is not here yet; yubico-piv-tool does it.
--
--  Byte-level facts encoded below, from SP 800-73-4 Part 2 and the Yubico
--  PIV extension notes: PIV AID A0 00 00 03 08; VERIFY 00 20 00 80 with an
--  8-byte FF-padded PIN; GET DATA 00 CB 3F FF with a 5C tag naming the
--  object (certificate objects 5F C1 05 / 0A / 0B / 01 for slots 9A / 9C /
--  9D / 9E), the response 53 { 70 cert, 71 01 00, FE 00 }; GENERAL
--  AUTHENTICATE 00 87 alg slot with 7C { 82 00, 81 digest }, the response
--  7C { 82 signature }. Algorithm identifiers 11 = ECC P-256, 14 = ECC
--  P-384, 07 = RSA 2048, 05 = RSA 3072, 16 = RSA 4096. ECDSA signatures
--  come back already DER-encoded (SEQUENCE { r, s }), which is the TLS wire
--  form. Responses longer than 256 bytes arrive through GET RESPONSE
--  (SW1 = 61); commands longer than 255 bytes go out chained (CLA 10).
with Interfaces;

package PIV with
  SPARK_Mode => On
is
   type Byte is new Interfaces.Unsigned_8;
   type Index is range 0 .. 2 ** 31 - 2;
   type Bytes is array (Index range <>) of Byte;

   --  Largest APDU the applet accepts in one command (short APDU), and the
   --  largest object we read back (a certificate object with chaining).
   Max_Command  : constant := 261;    --  4 header + 1 Lc + 255 data + 1 Le
   Max_Response : constant := 258;    --  256 data + SW1 SW2
   Max_Object   : constant := 3072;   --  certificate object upper bound

   --  The transport. Cmd is a complete APDU (CLA INS P1 P2 [Lc data] [Le]);
   --  Resp receives the response including the two status bytes;
   --  Resp_Len counts them. OK is False on any transport failure.
   type Transmit_Fn is access procedure
     (Cmd      : in     Bytes;
      Resp     :    out Bytes;
      Resp_Len :    out Index;
      OK       :    out Boolean);

   type Slot is (Slot_9A_Authentication, Slot_9C_Signature,
                 Slot_9D_Key_Management, Slot_9E_Card_Authentication);

   type Algorithm is (ECC_P256, ECC_P384, RSA_2048, RSA_3072, RSA_4096, Ed25519);
   --  Ed25519 (algorithm E0) needs YubiKey firmware 5.7 or later.

   type Status is
     (Success,
      Transport_Failure,       --  Transmit reported failure
      Card_Error,              --  applet returned an error status word
      Wrong_PIN,               --  63 CX: PIN wrong, X retries left
      PIN_Blocked,             --  69 83
      Security_Status,         --  69 82: PIN not verified for this slot
      Not_Found,               --  6A 82: no such object / empty slot
      Malformed_Response,      --  TLV did not parse as expected
      Buffer_Too_Small);       --  caller's buffer cannot hold the result

   --  Select the PIV applet. Must precede every other command on a fresh
   --  card connection.
   procedure Select_Applet (Transmit : Transmit_Fn; Result : out Status)
   with Pre => Transmit /= null;

   --  Verify the PIN (6 to 8 ASCII digits). On Wrong_PIN, Retries_Left
   --  holds the count the card reported; otherwise it is 0.
   procedure Verify_PIN
     (Transmit     : Transmit_Fn;
      PIN          : Bytes;
      Result       : out Status;
      Retries_Left : out Natural)
   with Pre => Transmit /= null and then PIN'Length in 6 .. 8;

   --  Read the X.509 certificate stored for a slot (DER, from the 70 tag
   --  of the certificate object). Cert_Len is 0 unless Result = Success.
   procedure Read_Certificate
     (Transmit : Transmit_Fn;
      S        : Slot;
      Cert     : out Bytes;
      Cert_Len : out Index;
      Result   : out Status)
   with
     Pre  => Transmit /= null and then Cert'First = 0 and then Cert'Length >= 1
             and then Cert'Length <= Max_Object,
     Post => Cert_Len <= Cert'Length and then (if Result /= Success then Cert_Len = 0);

   --  Sign with the key in a slot (the PIN must be verified first for
   --  slots 9A and 9C; 9E needs no PIN). Input is what the algorithm
   --  signs: the digest for ECDSA (32 bytes for P-256, 48 for P-384); for
   --  RSA the complete PKCS#1 v1.5 or PSS encoded block of modulus length,
   --  which the card exponentiates; for Ed25519 the whole message
   --  (PureEdDSA, the card hashes). Sig receives the signature as TLS
   --  carries it: DER SEQUENCE { r, s } for ECDSA, the modulus-length
   --  integer for RSA, 64 bytes for Ed25519. Sig_Len is 0 unless Success.
   procedure Sign
     (Transmit : Transmit_Fn;
      S        : Slot;
      Alg      : Algorithm;
      Input    : Bytes;
      Sig      : out Bytes;
      Sig_Len  : out Index;
      Result   : out Status)
   with
     Pre  => Transmit /= null and then Input'First = 0
             and then Input'Length in 1 .. 512
             and then Sig'First = 0 and then Sig'Length >= 1 and then Sig'Length <= 1024,
     Post => Sig_Len <= Sig'Length and then (if Result /= Success then Sig_Len = 0);

private

   PIV_AID : constant Bytes (0 .. 4) := (16#A0#, 16#00#, 16#00#, 16#03#, 16#08#);

   function Slot_Byte (S : Slot) return Byte
   is (case S is
         when Slot_9A_Authentication      => 16#9A#,
         when Slot_9C_Signature           => 16#9C#,
         when Slot_9D_Key_Management      => 16#9D#,
         when Slot_9E_Card_Authentication => 16#9E#);

   --  Certificate object identifier (last byte of 5F C1 xx) per slot.
   function Cert_Object_Byte (S : Slot) return Byte
   is (case S is
         when Slot_9A_Authentication      => 16#05#,
         when Slot_9C_Signature           => 16#0A#,
         when Slot_9D_Key_Management      => 16#0B#,
         when Slot_9E_Card_Authentication => 16#01#);

   function Alg_Byte (A : Algorithm) return Byte
   is (case A is
         when ECC_P256 => 16#11#,
         when ECC_P384 => 16#14#,
         when RSA_2048 => 16#07#,
         when RSA_3072 => 16#05#,
         when RSA_4096 => 16#16#,
         when Ed25519  => 16#E0#);

end PIV;
