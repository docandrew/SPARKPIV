package body PIV with
  SPARK_Mode => On
is
   --  ------------------------------------------------------------------
   --  Status words
   --  ------------------------------------------------------------------

   function SW_To_Status (SW1, SW2 : Byte) return Status
   is (if SW1 = 16#90# and then SW2 = 16#00# then Success
       elsif SW1 = 16#63# and then (SW2 and 16#F0#) = 16#C0# then Wrong_PIN
       elsif SW1 = 16#69# and then SW2 = 16#83# then PIN_Blocked
       elsif SW1 = 16#69# and then SW2 = 16#82# then Security_Status
       elsif SW1 = 16#6A# and then SW2 = 16#82# then Not_Found
       else Card_Error);

   --  ------------------------------------------------------------------
   --  Exchange: one logical command, with command chaining on the way
   --  out and GET RESPONSE collection on the way back. Data receives the
   --  concatenated response data (status words stripped); the final
   --  status word is mapped to Result.
   --  ------------------------------------------------------------------

   procedure Exchange
     (Transmit : Transmit_Fn;
      CLA, INS, P1, P2 : Byte;
      Cmd_Data : Bytes;
      Data     : out Bytes;
      Data_Len : out Index;
      SW1, SW2 : out Byte;
      Result   : out Status)
   with
     Pre  => Transmit /= null and then Cmd_Data'First = 0
             and then Cmd_Data'Length <= 4096
             and then Data'First = 0 and then Data'Length >= 1
             and then Data'Length <= Max_Object,
     Post => Data_Len <= Data'Length
   is
      Cmd      : Bytes (0 .. Max_Command - 1) := (others => 0);
      Resp     : Bytes (0 .. Max_Response - 1) := (others => 0);
      Resp_Len : Index;
      OK       : Boolean;
      Sent     : Index := 0;
      Total    : constant Index := Cmd_Data'Length;
   begin
      Data := (others => 0);
      Data_Len := 0;
      SW1 := 0;
      SW2 := 0;
      Result := Transport_Failure;

      --  Send the command, chaining 255-byte pieces (CLA or 10) until the
      --  last piece, which carries the real CLA and asks for a response.
      loop
         pragma Loop_Invariant (Sent <= Total);
         declare
            Remaining : constant Index := Total - Sent;
            Piece     : constant Index := (if Remaining > 255 then 255 else Remaining);
            Last      : constant Boolean := Remaining <= 255;
            Cmd_Len   : Index;
         begin
            Cmd := (others => 0);
            Cmd (0) := (if Last then CLA else (CLA or 16#10#));
            Cmd (1) := INS;
            Cmd (2) := P1;
            Cmd (3) := P2;
            if Piece > 0 then
               Cmd (4) := Byte (Piece);
               for I in Index range 0 .. Piece - 1 loop
                  pragma Loop_Invariant (I < Piece and then Sent + I < Total);
                  Cmd (5 + I) := Cmd_Data (Sent + I);
               end loop;
               Cmd_Len := 5 + Piece;
            else
               Cmd_Len := 4;
            end if;
            if Last then
               Cmd (Cmd_Len) := 16#00#;   --  Le: as much as the card has
               Cmd_Len := Cmd_Len + 1;
            end if;
            Transmit.all (Cmd (0 .. Cmd_Len - 1), Resp, Resp_Len, OK);
            if not OK or else Resp_Len < 2 or else Resp_Len > Resp'Length then
               Result := Transport_Failure;
               pragma Warnings (GNATprove, Off, "unused assignment",
                                Reason => "scrub of command data (may be the PIN); the store is kept by Inspection_Point");
               Cmd := (others => 0);
               pragma Warnings (GNATprove, On, "unused assignment");
               pragma Inspection_Point (Cmd);
               return;
            end if;
            SW1 := Resp (Resp_Len - 2);
            SW2 := Resp (Resp_Len - 1);
            Sent := Sent + Piece;
            if Last then
               exit;
            end if;
            --  An intermediate chained piece must be acknowledged 90 00.
            if SW1 /= 16#90# or else SW2 /= 16#00# then
               Result := SW_To_Status (SW1, SW2);
               pragma Warnings (GNATprove, Off, "unused assignment",
                                Reason => "scrub of command data (may be the PIN); the store is kept by Inspection_Point");
               Cmd := (others => 0);
               pragma Warnings (GNATprove, On, "unused assignment");
               pragma Inspection_Point (Cmd);
               return;
            end if;
         end;
      end loop;

      --  Collect response data, following 61 XX with GET RESPONSE.
      loop
         pragma Loop_Invariant (Data_Len <= Data'Length);
         pragma Loop_Invariant (Resp_Len >= 2 and then Resp_Len <= Resp'Length);
         declare
            Chunk : constant Index := Resp_Len - 2;
         begin
            if Chunk > 0 then
               if Data_Len + Chunk > Data'Length then
                  Data := (others => 0);
                  Data_Len := 0;
                  Result := Buffer_Too_Small;
                  return;
               end if;
               Data (Data_Len .. Data_Len + Chunk - 1) := Resp (0 .. Chunk - 1);
               Data_Len := Data_Len + Chunk;
            end if;
         end;
         exit when SW1 /= 16#61#;
         Cmd := (others => 0);
         Cmd (0) := 16#00#;
         Cmd (1) := 16#C0#;   --  GET RESPONSE
         Cmd (2) := 16#00#;
         Cmd (3) := 16#00#;
         Cmd (4) := SW2;      --  Le: what the card said is pending
         Transmit.all (Cmd (0 .. 4), Resp, Resp_Len, OK);
         if not OK or else Resp_Len < 2 or else Resp_Len > Resp'Length then
            Data := (others => 0);
            Data_Len := 0;
            Result := Transport_Failure;
            return;
         end if;
         SW1 := Resp (Resp_Len - 2);
         SW2 := Resp (Resp_Len - 1);
      end loop;

      Result := SW_To_Status (SW1, SW2);
      if Result /= Success then
         Data := (others => 0);
         Data_Len := 0;
      end if;
      --  Cmd carried the command data (the PIN, for VERIFY): scrub it.
      pragma Warnings (GNATprove, Off, "unused assignment",
                       Reason => "scrub of command data (may be the PIN); the store is kept by Inspection_Point");
      Cmd := (others => 0);
      pragma Warnings (GNATprove, On, "unused assignment");
      pragma Inspection_Point (Cmd);
   end Exchange;

   --  ------------------------------------------------------------------
   --  BER-TLV: one element at Pos in Buf (0 .. Len - 1). PIV tags are one
   --  byte, or two when the first byte's low five bits are all ones
   --  (5F C1 xx, 7F 49). Lengths are short, 81 xx, or 82 xx xx.
   --  ------------------------------------------------------------------

   procedure Parse_TLV
     (Buf     : Bytes;
      Len     : Index;
      Pos     : Index;
      Tag     : out Interfaces.Unsigned_16;   --  1-byte tag in the low byte
      Val_Pos : out Index;
      Val_Len : out Index;
      OK      : out Boolean)
   with
     Pre  => Buf'First = 0 and then Len <= Buf'Length and then Pos <= Len,
     Post => (if OK then Val_Pos <= Len and then Val_Len <= Len - Val_Pos)
   is
      use type Interfaces.Unsigned_16;
      P : Index := Pos;
   begin
      Tag := 0;
      Val_Pos := 0;
      Val_Len := 0;
      OK := False;
      if P >= Len then
         return;
      end if;
      Tag := Interfaces.Unsigned_16 (Buf (P));
      P := P + 1;
      if (Buf (Pos) and 16#1F#) = 16#1F# then
         if P >= Len then
            return;
         end if;
         Tag := Interfaces.Shift_Left (Tag, 8) or Interfaces.Unsigned_16 (Buf (P));
         P := P + 1;
      end if;
      if P >= Len then
         return;
      end if;
      declare
         L0 : constant Byte := Buf (P);
      begin
         P := P + 1;
         if L0 < 16#80# then
            Val_Len := Index (L0);
         elsif L0 = 16#81# then
            if P >= Len then
               return;
            end if;
            Val_Len := Index (Buf (P));
            P := P + 1;
         elsif L0 = 16#82# then
            if P + 1 >= Len then
               return;
            end if;
            Val_Len := Index (Buf (P)) * 256 + Index (Buf (P + 1));
            P := P + 2;
         else
            return;
         end if;
      end;
      if Val_Len > Len - P then
         Val_Len := 0;
         return;
      end if;
      Val_Pos := P;
      OK := True;
   end Parse_TLV;

   --  ------------------------------------------------------------------
   --  Commands
   --  ------------------------------------------------------------------

   procedure Select_Applet (Transmit : Transmit_Fn; Result : out Status) is
      Data     : Bytes (0 .. 255);
      Data_Len : Index;
      SW1, SW2 : Byte;
   begin
      --  00 A4 04 00 Lc AID : SELECT by name, first or only occurrence.
      Exchange (Transmit, 16#00#, 16#A4#, 16#04#, 16#00#, PIV_AID, Data, Data_Len, SW1, SW2, Result);
   end Select_Applet;

   procedure Verify_PIN
     (Transmit     : Transmit_Fn;
      PIN          : Bytes;
      Result       : out Status;
      Retries_Left : out Natural)
   is
      Padded   : Bytes (0 .. 7) := (others => 16#FF#);
      Data     : Bytes (0 .. 15);
      Data_Len : Index;
      SW1, SW2 : Byte;
   begin
      Retries_Left := 0;
      for I in Index range 0 .. PIN'Length - 1 loop
         pragma Loop_Invariant (I < PIN'Length);
         Padded (I) := PIN (PIN'First + I);
      end loop;
      --  00 20 00 80 08 PIN : VERIFY, key reference 80 = the PIV PIN.
      Exchange (Transmit, 16#00#, 16#20#, 16#00#, 16#80#, Padded, Data, Data_Len, SW1, SW2, Result);
      if Result = Wrong_PIN then
         Retries_Left := Natural (SW2 and 16#0F#);
      end if;
      --  Scrub the PIN copy. The Inspection_Point keeps the store: without
      --  it flow analysis calls this a dead assignment and the compiler
      --  may drop it.
      pragma Warnings (GNATprove, Off, "unused assignment",
                       Reason => "scrub of the PIN; the store is kept by Inspection_Point");
      Padded := (others => 0);
      pragma Warnings (GNATprove, On, "unused assignment");
      pragma Inspection_Point (Padded);
   end Verify_PIN;

   procedure Read_Certificate
     (Transmit : Transmit_Fn;
      S        : Slot;
      Cert     : out Bytes;
      Cert_Len : out Index;
      Result   : out Status)
   is
      use type Interfaces.Unsigned_16;
      --  5C 03 5F C1 xx : the object identifier of the slot's certificate.
      Req      : constant Bytes (0 .. 4) := (16#5C#, 16#03#, 16#5F#, 16#C1#, Cert_Object_Byte (S));
      Data     : Bytes (0 .. Max_Object - 1);
      Data_Len : Index;
      SW1, SW2 : Byte;
      Tag      : Interfaces.Unsigned_16;
      V_Pos, V_Len : Index;
      OK       : Boolean;
   begin
      Cert := (others => 0);
      Cert_Len := 0;
      --  00 CB 3F FF : GET DATA on the PIV application data objects.
      Exchange (Transmit, 16#00#, 16#CB#, 16#3F#, 16#FF#, Req, Data, Data_Len, SW1, SW2, Result);
      if Result /= Success then
         return;
      end if;
      --  53 L { 70 L cert  71 01 00  FE 00 }
      Parse_TLV (Data, Data_Len, 0, Tag, V_Pos, V_Len, OK);
      if not OK or else Tag /= 16#53# then
         Result := Malformed_Response;
         return;
      end if;
      declare
         Inner_End : constant Index := V_Pos + V_Len;
         P         : Index := V_Pos;
      begin
         while P < Inner_End loop
            pragma Loop_Invariant (P <= Inner_End and then Inner_End <= Data_Len);
            Parse_TLV (Data, Inner_End, P, Tag, V_Pos, V_Len, OK);
            if not OK then
               Result := Malformed_Response;
               return;
            end if;
            if Tag = 16#70# then
               if V_Len = 0 or else V_Len > Cert'Length then
                  Result := (if V_Len = 0 then Malformed_Response else Buffer_Too_Small);
                  return;
               end if;
               Cert (0 .. V_Len - 1) := Data (V_Pos .. V_Pos + V_Len - 1);
               Cert_Len := V_Len;
               Result := Success;
               return;
            end if;
            P := V_Pos + V_Len;
         end loop;
      end;
      Result := Malformed_Response;
   end Read_Certificate;

   procedure Sign
     (Transmit : Transmit_Fn;
      S        : Slot;
      Alg      : Algorithm;
      Input    : Bytes;
      Sig      : out Bytes;
      Sig_Len  : out Index;
      Result   : out Status)
   is
      use type Interfaces.Unsigned_16;
      --  Dynamic authentication template:
      --    7C L { 82 00 (response requested)  81 L digest (challenge) }
      D_Len    : constant Index := Input'Length;
      Inner    : constant Index := 2 + 2 + D_Len + (if D_Len < 128 then 0 elsif D_Len < 256 then 1 else 2);
      Req      : Bytes (0 .. 4 + 4 + 512 + 2) := (others => 0);
      Req_Len  : Index := 0;
      Data     : Bytes (0 .. 1023);
      Data_Len : Index;
      SW1, SW2 : Byte;
      Tag      : Interfaces.Unsigned_16;
      V_Pos, V_Len : Index;
      OK       : Boolean;

      procedure Put (B : Byte) with
        Pre  => Req_Len < Req'Length,
        Post => Req_Len = Req_Len'Old + 1
      is
      begin
         Req (Req_Len) := B;
         Req_Len := Req_Len + 1;
      end Put;

      --  Writes 1 to 3 bytes. The bound is stated without adding to
      --  Req_Len so the precondition itself cannot overflow.
      procedure Put_Length (L : Index) with
        Pre  => L <= 65535 and then Req_Len <= Req'Length - 3,
        Post => Req_Len >= Req_Len'Old + 1 and then Req_Len <= Req_Len'Old + 3
      is
      begin
         if L < 128 then
            Put (Byte (L));
         elsif L < 256 then
            Put (16#81#);
            Put (Byte (L));
         else
            Put (16#82#);
            Put (Byte (L / 256));
            Put (Byte (L mod 256));
         end if;
      end Put_Length;
   begin
      Sig := (others => 0);
      Sig_Len := 0;
      --  Header: at most 1 + 3 + 1 + 1 + 1 + 3 = 10 bytes, then the digest
      --  (at most 512): 522 bytes, inside Req's 523.
      Put (16#7C#);
      pragma Assert (Req_Len = 1);
      Put_Length (Inner);
      pragma Assert (Req_Len in 2 .. 4);
      Put (16#82#);
      Put (16#00#);
      Put (16#81#);
      pragma Assert (Req_Len in 5 .. 7);
      Put_Length (D_Len);
      pragma Assert (Req_Len in 6 .. 10);
      for I in Index range 0 .. D_Len - 1 loop
         pragma Loop_Invariant (Req_Len = Req_Len'Loop_Entry + I);
         pragma Loop_Invariant (Req_Len <= 10 + I);
         Put (Input (I));
      end loop;
      pragma Assert (Req_Len in 7 .. 522);
      --  00 87 alg slot : GENERAL AUTHENTICATE.
      Exchange (Transmit, 16#00#, 16#87#, Alg_Byte (Alg), Slot_Byte (S),
                Req (0 .. Req_Len - 1), Data, Data_Len, SW1, SW2, Result);
      if Result /= Success then
         return;
      end if;
      --  7C L { 82 L signature }
      Parse_TLV (Data, Data_Len, 0, Tag, V_Pos, V_Len, OK);
      if not OK or else Tag /= 16#7C# then
         Result := Malformed_Response;
         return;
      end if;
      declare
         Inner_End : constant Index := V_Pos + V_Len;
      begin
         Parse_TLV (Data, Inner_End, V_Pos, Tag, V_Pos, V_Len, OK);
      end;
      if not OK or else Tag /= 16#82# or else V_Len = 0 then
         Result := Malformed_Response;
         return;
      end if;
      if V_Len > Sig'Length then
         Result := Buffer_Too_Small;
         return;
      end if;
      Sig (0 .. V_Len - 1) := Data (V_Pos .. V_Pos + V_Len - 1);
      Sig_Len := V_Len;
   end Sign;

end PIV;
