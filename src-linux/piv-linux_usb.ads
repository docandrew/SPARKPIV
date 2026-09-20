--  PIV.Linux_USB: the Linux half of a CCID transport for SPARKPIV. Finds the
--  token through sysfs, claims its CCID interface through /dev/bus/usb
--  (usbfs ioctls; libc open/ioctl/close are the only foreign calls), and
--  supplies the two bulk-transfer callbacks that the SPARK PIV.CCID layer
--  drives. No pcscd, no libpcsclite, no libusb. Another host (CuBit, via IPC
--  to its USB service) implements the same two callbacks and reuses PIV.CCID
--  and PIV unchanged.
--
--  Optional: built by sparkpiv_linux.gpr, not by the core sparkpiv.gpr, so
--  the SPARK protocol crate stays free of OS dependencies. Not SPARK.
--
--  Needs write access to the device node (udev rule for idVendor 1050) and
--  no other process holding the interface (pcscd must not be running).
package PIV.Linux_USB is

   --  Find the first YubiKey (idVendor 1050) with a CCID interface, open
   --  it, claim the interface, power the card on. Info receives a short
   --  description for display.
   procedure Connect (Info : out String; Info_Len : out Natural; OK : out Boolean);

   --  The PIV.Transmit_Fn: one APDU in, one response (with SW1 SW2) out.
   procedure Transmit
     (Cmd      : in     Bytes;
      Resp     :    out Bytes;
      Resp_Len :    out Index;
      OK       :    out Boolean);

   procedure Disconnect;

end PIV.Linux_USB;
