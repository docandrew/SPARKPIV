--  PIV.Linux_USB: a plain-Ada CCID transport for SPARKPIV on Linux. Talks to
--  the YubiKey's smart-card interface directly through /dev/bus/usb (usbfs
--  ioctls; libc open/ioctl/close are the only foreign calls), no pcscd, no
--  libpcsclite, no libusb. The CCID layer (USB CCID rev 1.1,
--  PC_to_RDR_XfrBlock / RDR_to_PC_DataBlock) is the same one a native driver
--  on CuBit implements above its USB host stack.
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
