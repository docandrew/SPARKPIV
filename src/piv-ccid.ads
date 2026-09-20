--  PIV.CCID: USB CCID (Chip Card Interface Device, rev 1.1) message framing
--  in SPARK. This is the layer between APDUs and USB bulk transfers: it
--  wraps a command in PC_to_RDR_XfrBlock, unwraps RDR_to_PC_DataBlock,
--  checks the sequence number, honours time-extension requests and reports
--  card status. It owns no I/O: the caller supplies two bulk-transfer
--  callbacks (a usbfs ioctl on Linux, an IPC message to a USB service on
--  CuBit, ...), so the code that consumes bytes from the device is proven
--  here and the OS-specific part shrinks to those two calls.
package PIV.CCID with
  SPARK_Mode => On
is
   Header_Len   : constant := 10;
   Max_Payload  : constant := 4096;              --  one APDU or response
   Max_Message  : constant := Header_Len + Max_Payload;

   --  Write Data to the bulk OUT endpoint. OK False on failure.
   type Bulk_Out_Fn is access procedure (Data : in Bytes; OK : out Boolean);

   --  Read one bulk IN transfer into Data (Len bytes). OK False on failure
   --  or timeout. Data'Length is the most the caller will accept.
   type Bulk_In_Fn is access procedure (Data : out Bytes; Len : out Index; OK : out Boolean);

   type Reader is record
      Bulk_Out : Bulk_Out_Fn := null;
      Bulk_In  : Bulk_In_Fn := null;
      Seq      : Byte := 0;      --  bSeq of the last message sent
      Slot     : Byte := 0;      --  bSlot; a YubiKey has one
   end record;

   function Ready (R : Reader) return Boolean
   is (R.Bulk_Out /= null and then R.Bulk_In /= null);

   --  PC_to_RDR_IccPowerOn (62): power the card, receive its ATR.
   procedure Power_On
     (R       : in out Reader;
      ATR     :    out Bytes;
      ATR_Len :    out Index;
      OK      :    out Boolean)
   with
     Pre  => Ready (R) and then ATR'First = 0 and then ATR'Length in 1 .. Max_Payload,
     Post => ATR_Len <= ATR'Length and then (if not OK then ATR_Len = 0);

   --  PC_to_RDR_XfrBlock (6F): send one APDU, receive its response
   --  (data plus SW1 SW2) from the RDR_to_PC_DataBlock (80).
   procedure Transfer
     (R        : in out Reader;
      APDU     : in     Bytes;
      Resp     :    out Bytes;
      Resp_Len :    out Index;
      OK       :    out Boolean)
   with
     Pre  => Ready (R) and then APDU'First = 0 and then APDU'Length in 1 .. Max_Payload
             and then Resp'First = 0 and then Resp'Length in 1 .. Max_Payload,
     Post => Resp_Len <= Resp'Length and then (if not OK then Resp_Len = 0);

end PIV.CCID;
