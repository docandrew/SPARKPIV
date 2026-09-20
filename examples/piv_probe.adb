--  piv_probe: what is in a PIV token's slots, without the PIN. Reading a
--  slot's certificate object needs no PIN. Prints each slot's certificate
--  size and, with an output directory, writes the DER so
--  `openssl x509 -inform der -in 9e.der -text` can show the key type.
--
--    piv_probe [out_dir]
with Ada.Command_Line;
with Ada.Text_IO;          use Ada.Text_IO;
with Ada.Streams.Stream_IO;
with PIV;                  use PIV;
with PIV.Linux_USB;

procedure PIV_Probe is
   T     : constant Transmit_Fn := Linux_USB.Transmit'Access;
   Info  : String (1 .. 128);
   I_Len : Natural;
   OK    : Boolean;
   R     : Status;

   function Slot_Name (S : Slot) return String
   is (case S is
         when Slot_9A_Authentication      => "9a",
         when Slot_9C_Signature           => "9c",
         when Slot_9D_Key_Management      => "9d",
         when Slot_9E_Card_Authentication => "9e");

   procedure Dump (Name : String; Cert : Bytes; Len : Index) is
      use Ada.Streams.Stream_IO;
      F : File_Type;
      SE : Ada.Streams.Stream_Element_Array (1 .. Ada.Streams.Stream_Element_Offset (Len));
   begin
      for I in SE'Range loop
         SE (I) := Ada.Streams.Stream_Element (Cert (Index (I) - 1));
      end loop;
      Create (F, Out_File, Name);
      Write (F, SE);
      Close (F);
      Put_Line ("     wrote " & Name);
   end Dump;
begin
   Linux_USB.Connect (Info, I_Len, OK);
   if not OK then
      Put_Line ("No PIV token reachable over USB (inserted? udev rule? pcscd running?)");
      return;
   end if;
   Put_Line ("Token: " & Info (1 .. I_Len));
   Select_Applet (T, R);
   Put_Line ("SELECT PIV: " & R'Image);
   if R = Success then
      for S in Slot loop
         declare
            Cert  : Bytes (0 .. Max_Object - 1);
            C_Len : Index;
         begin
            Read_Certificate (T, S, Cert, C_Len, R);
            if R = Not_Found then
               Put_Line ("  slot " & Slot_Name (S) & ": empty");
            elsif R /= Success then
               Put_Line ("  slot " & Slot_Name (S) & ": " & R'Image);
            else
               Put_Line ("  slot " & Slot_Name (S) & ": certificate," & C_Len'Image & " bytes DER");
               if Ada.Command_Line.Argument_Count >= 1 then
                  Dump (Ada.Command_Line.Argument (1) & "/" & Slot_Name (S) & ".der", Cert, C_Len);
               end if;
            end if;
         end;
      end loop;
   end if;
   Linux_USB.Disconnect;
end PIV_Probe;
