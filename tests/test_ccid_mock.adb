--  PIV.CCID against a scripted reader: framing, sequence check, time
--  extension, command failure, oversized length claims.
with Ada.Text_IO; use Ada.Text_IO;
with PIV;         use PIV;
with PIV.CCID;    use PIV.CCID;

procedure Test_CCID_Mock is
   Total, Pass, Fail : Natural := 0;
   procedure Check (Name : String; OK : Boolean) is
   begin
      Total := Total + 1;
      if OK then Pass := Pass + 1; Put_Line ("  PASS: " & Name);
      else Fail := Fail + 1; Put_Line ("  FAIL: " & Name); end if;
   end Check;

   Last_Out : Bytes (0 .. 4105) := (others => 0);
   Last_Len : Index := 0;
   Script   : Natural := 0;     --  which reply behaviour
   Reads    : Natural := 0;

   procedure Out_Fn (Data : in Bytes; OK : out Boolean) is
   begin
      Last_Out := (others => 0);
      Last_Out (0 .. Data'Length - 1) := Data;
      Last_Len := Data'Length;
      Reads := 0;
      OK := True;
   end Out_Fn;

   procedure In_Fn (Data : out Bytes; Len : out Index; OK : out Boolean) is
      Seq : constant Byte := Last_Out (6);
      procedure Block (Status : Byte; Payload : Bytes) is
         L : constant Index := Payload'Length;
      begin
         Data := (others => 0);
         Data (0) := 16#80#;
         Data (1) := Byte (L mod 256); Data (2) := Byte (L / 256); Data (3) := 0; Data (4) := 0;
         Data (5) := 0; Data (6) := Seq; Data (7) := Status; Data (8) := 0; Data (9) := 0;
         if L > 0 then Data (10 .. 10 + L - 1) := Payload; end if;
         Len := 10 + L;
         OK := True;
      end Block;
      Reply : constant Bytes (0 .. 3) := (16#90#, 16#00#, 16#AA#, 16#BB#);
   begin
      Reads := Reads + 1;
      case Script is
         when 0 => Block (16#00#, (16#3B#, 16#FD#, 16#13#, 16#00#));            --  ATR-ish / data
         when 1 =>   --  time extension first, then the data
            if Reads = 1 then Block (16#80#, Reply (1 .. 0)); else Block (0, Reply); end if;
         when 2 => Block (16#40#, Reply (1 .. 0));                              --  command failed
         when 3 => Block (16#00#, Reply); Data (6) := Seq + 1;                  --  wrong sequence
         when 4 => Block (16#00#, Reply); Data (1) := 16#FF#; Data (2) := 16#0F#; --  claims 4095 bytes, sent 4
         when others => OK := False; Len := 0; Data := (others => 0);
      end case;
   end In_Fn;

   R    : Reader := (Bulk_Out => Out_Fn'Unrestricted_Access, Bulk_In => In_Fn'Unrestricted_Access, Seq => 0, Slot => 0);
   Resp : Bytes (0 .. 255);
   L    : Index;
   OK   : Boolean;
   APDU : constant Bytes (0 .. 4) := (16#00#, 16#A4#, 16#04#, 16#00#, 16#00#);
begin
   Script := 0;
   Power_On (R, Resp, L, OK);
   Check ("Power_On frames PC_to_RDR_IccPowerOn (62) with seq 1", OK and Last_Out (0) = 16#62# and Last_Out (6) = 1 and Last_Len = 10);
   Check ("Power_On returns the ATR bytes", L = 4 and Resp (0) = 16#3B#);
   Transfer (R, APDU, Resp, L, OK);
   Check ("Transfer frames XfrBlock (6F), dwLength 5, seq 2, APDU after the header",
          OK and Last_Out (0) = 16#6F# and Last_Out (1) = 5 and Last_Out (6) = 2 and Last_Out (10 .. 14) = APDU);
   Script := 1;
   Transfer (R, APDU, Resp, L, OK);
   Check ("time extension: re-read, then data", OK and Reads = 2 and L = 4 and Resp (0 .. 1) = (16#90#, 16#00#));
   Script := 2;
   Transfer (R, APDU, Resp, L, OK);
   Check ("command failed status: not OK, no data", not OK and L = 0);
   Script := 3;
   Transfer (R, APDU, Resp, L, OK);
   Check ("foreign sequence number: rejected", not OK and L = 0);
   Script := 4;
   Transfer (R, APDU, Resp, L, OK);
   Check ("dwLength larger than the block: rejected", not OK and L = 0);
   Script := 9;
   Transfer (R, APDU, Resp, L, OK);
   Check ("transport failure: not OK", not OK and L = 0);
   Put_Line ("Total:" & Total'Image & "  Pass:" & Pass'Image & "  Fail:" & Fail'Image);
end Test_CCID_Mock;
