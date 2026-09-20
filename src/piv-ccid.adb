with Interfaces;

package body PIV.CCID with
  SPARK_Mode => On
is
   use type Interfaces.Unsigned_32;

   --  One CCID command (10-byte header || payload) and its response. The
   --  response loop re-reads on a time-extension request (bStatus command
   --  status = 2) and fails on command failure (= 1), a foreign sequence
   --  number, a short or oversized block, or a transport failure.
   procedure Exchange
     (R        : in out Reader;
      Msg_Type : in     Byte;
      Extra    : in     Bytes;        --  the three message-specific header bytes
      Payload  : in     Bytes;
      Data     :    out Bytes;
      Data_Len :    out Index;
      OK       :    out Boolean)
   with
     Pre  => Ready (R) and then Extra'First = 0 and then Extra'Length = 3
             and then Payload'First = 0 and then Payload'Length <= Max_Payload
             and then Data'First = 0 and then Data'Length in 1 .. Max_Payload,
     Post => Data_Len <= Data'Length and then (if not OK then Data_Len = 0)
   is
      Msg     : Bytes (0 .. Max_Message - 1) := (others => 0);
      Msg_Len : constant Index := Header_Len + Payload'Length;
      Rsp     : Bytes (0 .. Max_Message - 1) := (others => 0);
      Rsp_Len : Index;
      L       : constant Interfaces.Unsigned_32 := Interfaces.Unsigned_32 (Payload'Length);
      X_OK    : Boolean;
   begin
      Data := (others => 0);
      Data_Len := 0;
      OK := False;
      R.Seq := R.Seq + 1;   --  wraps mod 256, as bSeq does
      Msg (0) := Msg_Type;
      Msg (1) := Byte (L and 16#FF#);
      Msg (2) := Byte (Interfaces.Shift_Right (L, 8) and 16#FF#);
      Msg (3) := Byte (Interfaces.Shift_Right (L, 16) and 16#FF#);
      Msg (4) := Byte (Interfaces.Shift_Right (L, 24) and 16#FF#);
      Msg (5) := R.Slot;
      Msg (6) := R.Seq;
      Msg (7 .. 9) := Extra;
      if Payload'Length > 0 then
         Msg (Header_Len .. Msg_Len - 1) := Payload;
      end if;
      R.Bulk_Out.all (Msg (0 .. Msg_Len - 1), X_OK);
      if not X_OK then
         return;
      end if;
      --  Up to a handful of time-extension rounds; a card asking forever
      --  is treated as failed rather than looping without bound.
      for Round in 1 .. 16 loop
         R.Bulk_In.all (Rsp, Rsp_Len, X_OK);
         if not X_OK or else Rsp_Len < Header_Len or else Rsp_Len > Rsp'Length then
            return;
         end if;
         declare
            --  bStatus bits 7..6: 0 processed, 1 failed, 2 time extension.
            Cmd_Status : constant Byte := (Rsp (7) / 64) and 3;
            D_Len      : constant Index :=
              Index (Rsp (1)) + 256 * Index (Rsp (2)) + 65536 * Index (Rsp (3));
         begin
            if Rsp (6) /= R.Seq then
               return;                  --  not the answer to our message
            end if;
            if Cmd_Status = 1 then
               return;                  --  failed; bError is in Rsp (8)
            elsif Cmd_Status = 0 then
               if D_Len > Data'Length or else D_Len > Rsp_Len - Header_Len then
                  return;               --  claims more than it sent or than we take
               end if;
               if D_Len > 0 then
                  Data (0 .. D_Len - 1) := Rsp (Header_Len .. Header_Len + D_Len - 1);
               end if;
               Data_Len := D_Len;
               OK := True;
               return;
            end if;
            --  Cmd_Status 2: time extension requested; read again.
         end;
      end loop;
   end Exchange;

   procedure Power_On
     (R       : in out Reader;
      ATR     :    out Bytes;
      ATR_Len :    out Index;
      OK      :    out Boolean)
   is
      None  : constant Bytes (0 .. -1) := (others => 0);
      Extra : constant Bytes (0 .. 2) := (0, 0, 0);   --  bPowerSelect auto, RFU
   begin
      Exchange (R, 16#62#, Extra, None, ATR, ATR_Len, OK);
   end Power_On;

   procedure Transfer
     (R        : in out Reader;
      APDU     : in     Bytes;
      Resp     :    out Bytes;
      Resp_Len :    out Index;
      OK       :    out Boolean)
   is
      Extra : constant Bytes (0 .. 2) := (0, 0, 0);   --  bBWI 0, wLevelParameter 0
   begin
      Exchange (R, 16#6F#, Extra, APDU, Resp, Resp_Len, OK);
   end Transfer;

end PIV.CCID;
