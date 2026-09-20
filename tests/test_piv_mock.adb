--  SPARKPIV against a scripted transport: no hardware. Checks the APDUs the
--  client emits and its handling of status words, TLV, GET RESPONSE
--  chaining (61 XX) and command chaining (CLA 10) on a long GENERAL
--  AUTHENTICATE payload.
with Ada.Text_IO; use Ada.Text_IO;
with PIV;         use PIV;

procedure Test_PIV_Mock is
   Total, Pass, Fail : Natural := 0;
   procedure Check (Name : String; OK : Boolean) is
   begin
      Total := Total + 1;
      if OK then Pass := Pass + 1; Put_Line ("  PASS: " & Name);
      else Fail := Fail + 1; Put_Line ("  FAIL: " & Name); end if;
   end Check;

   --  The mock: records the last command, replies from a small script.
   Last_Cmd     : Bytes (0 .. 300) := (others => 0);
   Last_Cmd_Len : Index := 0;
   Cmd_Count    : Natural := 0;
   Mode         : Natural := 0;   --  selects the scripted behaviour

   --  A fake certificate object: 53 L { 70 L <cert> 71 01 00 FE 00 } where
   --  <cert> is 300 bytes of pattern, so the response must be chained.
   Cert_Len  : constant := 300;
   function Cert_Byte (I : Index) return Byte is (Byte (I mod 251));

   Obj : Bytes (0 .. 4 + 4 + Cert_Len + 3 + 2 - 1);
   Obj_Len : Index;

   procedure Build_Object is
      P : Index := 0;
      procedure Put (B : Byte) is begin Obj (P) := B; P := P + 1; end Put;
      Inner : constant Index := 4 + Cert_Len + 3 + 2;   --  70 82 L L cert, 71 01 00, FE 00
   begin
      Put (16#53#); Put (16#82#); Put (Byte (Inner / 256)); Put (Byte (Inner mod 256));
      Put (16#70#); Put (16#82#); Put (Byte (Cert_Len / 256)); Put (Byte (Cert_Len mod 256));
      for I in Index range 0 .. Cert_Len - 1 loop Put (Cert_Byte (I)); end loop;
      Put (16#71#); Put (16#01#); Put (16#00#);
      Put (16#FE#); Put (16#00#);
      Obj_Len := P;
   end Build_Object;

   Sent_So_Far : Index := 0;   --  for chained responses
   GetData_Cmd : Bytes (0 .. 15) := (others => 0);   --  the 00 CB 3F FF command as sent

   procedure Mock
     (Cmd      : in     Bytes;
      Resp     :    out Bytes;
      Resp_Len :    out Index;
      OK       :    out Boolean)
   is
      procedure Reply (Data : Bytes; SW1, SW2 : Byte) is
      begin
         Resp := (others => 0);
         Resp (0 .. Data'Length - 1) := Data;
         Resp (Data'Length) := SW1;
         Resp (Data'Length + 1) := SW2;
         Resp_Len := Data'Length + 2;
         OK := True;
      end Reply;
      None : constant Bytes (1 .. 0) := (others => 0);
   begin
      Cmd_Count := Cmd_Count + 1;
      Last_Cmd := (others => 0);
      Last_Cmd (0 .. Cmd'Length - 1) := Cmd;
      Last_Cmd_Len := Cmd'Length;
      Resp := (others => 0); Resp_Len := 0; OK := False;

      if Cmd (1) = 16#C0# then
         --  GET RESPONSE: next chunk of the object.
         declare
            Remaining : constant Index := Obj_Len - Sent_So_Far;
            Chunk     : constant Index := (if Remaining > 256 then 256 else Remaining);
            After     : constant Index := Remaining - Chunk;
         begin
            Reply (Obj (Sent_So_Far .. Sent_So_Far + Chunk - 1),
                   (if After > 0 then 16#61# else 16#90#),
                   (if After > 0 then Byte (if After > 255 then 0 else After) else 16#00#));
            Sent_So_Far := Sent_So_Far + Chunk;
         end;
         return;
      end if;

      case Cmd (1) is
         when 16#A4# =>                       --  SELECT
            Reply (None, 16#90#, 16#00#);
         when 16#20# =>                       --  VERIFY
            if Mode = 1 then Reply (None, 16#63#, 16#C2#);   --  wrong PIN, 2 left
            elsif Mode = 2 then Reply (None, 16#69#, 16#83#);   --  blocked
            else Reply (None, 16#90#, 16#00#); end if;
         when 16#CB# =>                       --  GET DATA: first 256 bytes, more pending
            GetData_Cmd (0 .. Cmd'Length - 1) := Cmd;
            Sent_So_Far := 256;
            Reply (Obj (0 .. 255), 16#61#, 16#00#);
         when 16#87# =>                       --  GENERAL AUTHENTICATE
            if (Cmd (0) and 16#10#) /= 0 then
               Reply (None, 16#90#, 16#00#);  --  ack a chained piece
            else
               --  7C 08 { 82 06 <6 sig bytes> }
               Reply ((16#7C#, 16#08#, 16#82#, 16#06#, 1, 2, 3, 4, 5, 6), 16#90#, 16#00#);
            end if;
         when others =>
            Reply (None, 16#6D#, 16#00#);     --  INS not supported
      end case;
   end Mock;

   T : constant Transmit_Fn := Mock'Unrestricted_Access;
   R : Status;
begin
   Build_Object;

   Select_Applet (T, R);
   Check ("SELECT succeeds", R = Success);
   Check ("SELECT APDU is 00 A4 04 00 05 A0 00 00 03 08 00",
          Last_Cmd_Len = 11 and then Last_Cmd (0 .. 10) =
            (16#00#, 16#A4#, 16#04#, 16#00#, 16#05#, 16#A0#, 16#00#, 16#00#, 16#03#, 16#08#, 16#00#));

   declare
      Retries : Natural;
      PIN : constant Bytes (0 .. 5) := (16#31#, 16#32#, 16#33#, 16#34#, 16#35#, 16#36#);
   begin
      Mode := 0;
      Verify_PIN (T, PIN, R, Retries);
      Check ("VERIFY succeeds", R = Success);
      Check ("VERIFY APDU pads the PIN with FF to 8 bytes",
             Last_Cmd_Len = 14 and then Last_Cmd (0 .. 4) = (16#00#, 16#20#, 16#00#, 16#80#, 16#08#)
             and then Last_Cmd (5 .. 10) = PIN and then Last_Cmd (11 .. 12) = (16#FF#, 16#FF#));
      Mode := 1;
      Verify_PIN (T, PIN, R, Retries);
      Check ("wrong PIN reported with retries left = 2", R = Wrong_PIN and Retries = 2);
      Mode := 2;
      Verify_PIN (T, PIN, R, Retries);
      Check ("blocked PIN reported", R = PIN_Blocked);
      Mode := 0;
   end;

   declare
      Cert : Bytes (0 .. 1023);
      C_Len : Index;
   begin
      Cmd_Count := 0;
      Read_Certificate (T, Slot_9C_Signature, Cert, C_Len, R);
      Check ("GET DATA succeeds through 61 XX chaining", R = Success);
      Check ("GET DATA APDU is 00 CB 3F FF 05 5C 03 5F C1 0A 00 (slot 9C)",
             GetData_Cmd (0 .. 10) = (16#00#, 16#CB#, 16#3F#, 16#FF#, 16#05#, 16#5C#, 16#03#, 16#5F#, 16#C1#, 16#0A#, 16#00#));
      Check ("certificate extracted from tag 70 with the right length", C_Len = Cert_Len);
      Check ("certificate bytes intact across chunk boundaries",
             (for all I in Index range 0 .. Cert_Len - 1 => Cert (I) = Cert_Byte (I)));
      Check ("chaining used GET RESPONSE (more than one command)", Cmd_Count > 1);
   end;

   declare
      Digest : constant Bytes (0 .. 31) := (others => 16#AB#);
      Sig    : Bytes (0 .. 255);
      S_Len  : Index;
   begin
      Sign (T, Slot_9C_Signature, ECC_P256, Digest, Sig, S_Len, R);
      Check ("GENERAL AUTHENTICATE succeeds", R = Success);
      Check ("signature extracted from 7C { 82 }", S_Len = 6 and then Sig (0 .. 5) = (1, 2, 3, 4, 5, 6));
      Check ("GENERAL AUTHENTICATE header 00 87 11 9C",
             Last_Cmd (0 .. 3) = (16#00#, 16#87#, 16#11#, 16#9C#));
      Check ("template 7C { 82 00, 81 20 digest }",
             Last_Cmd (5 .. 10) = (16#7C#, 16#24#, 16#82#, 16#00#, 16#81#, 16#20#)
             and then Last_Cmd (11 .. 42) = Digest);
   end;

   declare
      Msg   : constant Bytes (0 .. 145) := (others => 16#42#);   --  a TLS 1.3 CV content
      Sig   : Bytes (0 .. 255);
      S_Len : Index;
   begin
      Sign (T, Slot_9C_Signature, Ed25519, Msg, Sig, S_Len, R);
      Check ("Ed25519: GENERAL AUTHENTICATE with algorithm E0 over the message",
             R = Success and then Last_Cmd (0 .. 3) = (16#00#, 16#87#, 16#E0#, 16#9C#)
             and then Last_Cmd (5 .. 6) = (16#7C#, 16#81#));   --  7C 81 96: long-form length
   end;

   declare
      --  A 512-byte RSA block forces command chaining (payload > 255).
      Block : constant Bytes (0 .. 511) := (others => 16#5C#);
      Sig   : Bytes (0 .. 1023);
      S_Len : Index;
   begin
      Cmd_Count := 0;
      Sign (T, Slot_9C_Signature, RSA_4096, Block, Sig, S_Len, R);
      Check ("long payload: command chaining completes", R = Success);
      Check ("long payload: more than one command piece sent", Cmd_Count >= 3);
      Check ("long payload: final piece has plain CLA 00", Last_Cmd (0) = 16#00#);
   end;

   Put_Line ("Total:" & Total'Image & "  Pass:" & Pass'Image & "  Fail:" & Fail'Image);
end Test_PIV_Mock;
