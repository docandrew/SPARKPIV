with Ada.Directories;           use Ada.Directories;
with Ada.Text_IO;
with Ada.Strings.Fixed;
with Interfaces;                use Interfaces;
with Interfaces.C;              use Interfaces.C;
with Interfaces.C.Strings;
with System;
with PIV.CCID;

package body PIV.Linux_USB is

   ----------------------------------------------------------------------
   --  libc syscall wrappers (open, ioctl, close): the OS boundary.
   ----------------------------------------------------------------------
   O_RDWR : constant int := 2;

   function C_Open (Path : Interfaces.C.Strings.chars_ptr; Flags : int) return int
   with Import, Convention => C, External_Name => "open";
   function C_Close (FD : int) return int
   with Import, Convention => C, External_Name => "close";
   function C_Ioctl (FD : int; Request : unsigned_long; Arg : System.Address) return int
   with Import, Convention => C, External_Name => "ioctl";

   --  linux/usbdevice_fs.h request codes (x86_64 _IOC encoding).
   USBDEVFS_CLAIMINTERFACE   : constant unsigned_long := 16#8004_550F#;
   USBDEVFS_RELEASEINTERFACE : constant unsigned_long := 16#8004_5510#;
   USBDEVFS_BULK             : constant unsigned_long := 16#C018_5502#;
   USBDEVFS_IOCTL            : constant unsigned_long := 16#C010_5512#;
   USBDEVFS_DISCONNECT       : constant int := 16#5516#;

   type Bulk_Transfer is record
      EP      : unsigned;
      Len     : unsigned;
      Timeout : unsigned;      --  ms
      Pad     : unsigned := 0;
      Data    : System.Address;
   end record with Convention => C;

   type Usbfs_Ioctl is record
      Ifno       : int;
      Ioctl_Code : int;
      Data       : System.Address;
   end record with Convention => C;

   ----------------------------------------------------------------------
   --  Device state
   ----------------------------------------------------------------------
   FD        : int := -1;
   Iface     : unsigned := 0;
   EP_Out    : unsigned := 0;
   EP_In     : unsigned := 0;
   Connected : Boolean := False;

   function Read_Sysfs (Path : String) return String is
      use Ada.Text_IO;
      F : File_Type;
   begin
      Open (F, In_File, Path);
      declare
         L : constant String := Get_Line (F);
      begin
         Close (F);
         return Ada.Strings.Fixed.Trim (L, Ada.Strings.Both);
      end;
   exception
      when others => return "";
   end Read_Sysfs;

   function Hex_Byte (S : String) return Unsigned_8 is
      V : Unsigned_8 := 0;
   begin
      for C of S loop
         V := V * 16 +
           (case C is
              when '0' .. '9' => Character'Pos (C) - Character'Pos ('0'),
              when 'a' .. 'f' => Character'Pos (C) - Character'Pos ('a') + 10,
              when 'A' .. 'F' => Character'Pos (C) - Character'Pos ('A') + 10,
              when others     => 0);
      end loop;
      return V;
   end Hex_Byte;

   --  Find the YubiKey's CCID interface via sysfs: a device with idVendor
   --  1050, an interface dir <dev>:1.<n> whose bInterfaceClass is 0b, and
   --  that interface's bulk IN and OUT endpoints. Fills the device node
   --  path and the endpoint numbers.
   procedure Locate (Node : out String; Node_Len : out Natural; OK : out Boolean) is
      Base : constant String := "/sys/bus/usb/devices";
      Srch : Search_Type;
      Ent  : Directory_Entry_Type;
   begin
      Node := (others => ' ');
      Node_Len := 0;
      OK := False;
      Start_Search (Srch, Base, "*", (Directory => True, others => False));
      while More_Entries (Srch) loop
         Get_Next_Entry (Srch, Ent);
         declare
            Name : constant String := Simple_Name (Ent);
            Dir  : constant String := Base & "/" & Name;
         begin
            if Name (Name'First) in '0' .. '9'
              and then Ada.Strings.Fixed.Index (Name, ":") = 0
              and then Read_Sysfs (Dir & "/idVendor") = "1050"
            then
               --  Interfaces of this device: <Name>:1.<n>
               for N in 0 .. 7 loop
                  declare
                     IDir : constant String := Base & "/" & Name & ":1." & Character'Val (Character'Pos ('0') + N);
                  begin
                     if Exists (IDir) and then Read_Sysfs (IDir & "/bInterfaceClass") = "0b" then
                        Iface := unsigned (N);
                        declare
                           ES : Search_Type;
                           EE : Directory_Entry_Type;
                        begin
                           Start_Search (ES, IDir, "ep_*", (Directory => True, others => False));
                           while More_Entries (ES) loop
                              Get_Next_Entry (ES, EE);
                              declare
                                 EName : constant String := Simple_Name (EE);   --  ep_02 / ep_82
                                 EDir  : constant String := IDir & "/" & EName;
                                 Addr  : constant Unsigned_8 := Hex_Byte (EName (EName'First + 3 .. EName'Last));
                              begin
                                 if Read_Sysfs (EDir & "/type") = "Bulk" then
                                    if Read_Sysfs (EDir & "/direction") = "in" then
                                       EP_In := unsigned (Addr);
                                    else
                                       EP_Out := unsigned (Addr);
                                    end if;
                                 end if;
                              end;
                           end loop;
                           End_Search (ES);
                        end;
                        if EP_In /= 0 and EP_Out /= 0 then
                           declare
                              Bus : constant String := Read_Sysfs (Dir & "/busnum");
                              Dev : constant String := Read_Sysfs (Dir & "/devnum");
                              P   : constant String :=
                                "/dev/bus/usb/" & (1 .. 3 - Bus'Length => '0') & Bus
                                & "/" & (1 .. 3 - Dev'Length => '0') & Dev;
                           begin
                              Node_Len := P'Length;
                              Node (Node'First .. Node'First + P'Length - 1) := P;
                              OK := True;
                              End_Search (Srch);
                              return;
                           end;
                        end if;
                     end if;
                  end;
               end loop;
            end if;
         end;
      end loop;
      End_Search (Srch);
   end Locate;

   ----------------------------------------------------------------------
   --  The two bulk-transfer callbacks PIV.CCID drives; everything above
   --  them (framing, sequence numbers, status) is the SPARK CCID layer.
   ----------------------------------------------------------------------
   procedure Bulk_Out (Data : in Bytes; OK : out Boolean) is
      Buf : aliased array (0 .. Natural (Data'Length) - 1) of Unsigned_8;
      T   : aliased Bulk_Transfer :=
        (EP => EP_Out, Len => unsigned (Data'Length), Timeout => 5000, Pad => 0, Data => Buf'Address);
   begin
      for I in Buf'Range loop
         Buf (I) := Unsigned_8 (Data (Data'First + Index (I)));
      end loop;
      OK := Integer (C_Ioctl (FD, USBDEVFS_BULK, T'Address)) = Buf'Length;
      --  The copy may hold a VERIFY APDU (the PIN): scrub it.
      Buf := (others => 0);
      pragma Inspection_Point (Buf);
   end Bulk_Out;

   procedure Bulk_In (Data : out Bytes; Len : out Index; OK : out Boolean) is
      Buf : aliased array (0 .. Natural (Data'Length) - 1) of Unsigned_8 := (others => 0);
      T   : aliased Bulk_Transfer :=
        (EP => EP_In, Len => unsigned (Data'Length), Timeout => 10000, Pad => 0, Data => Buf'Address);
      N   : constant Integer := Integer (C_Ioctl (FD, USBDEVFS_BULK, T'Address));
   begin
      Data := (others => 0);
      Len := 0;
      OK := False;
      if N < 0 or else N > Buf'Length then
         return;
      end if;
      for I in 0 .. N - 1 loop
         Data (Data'First + Index (I)) := Byte (Buf (I));
      end loop;
      Len := Index (N);
      OK := True;
   end Bulk_In;

   Card : CCID.Reader := (Bulk_Out => Bulk_Out'Access, Bulk_In => Bulk_In'Access, Seq => 0, Slot => 0);

   procedure Connect (Info : out String; Info_Len : out Natural; OK : out Boolean) is
      Node    : String (1 .. 64);
      N_Len   : Natural;
      Found   : Boolean;
      R       : int;
      ATR     : Bytes (0 .. 63);
      ATR_Len : Index;
      X_OK    : Boolean;
   begin
      Info := (others => ' ');
      Info_Len := 0;
      OK := False;
      if Connected then
         Disconnect;                 --  a second Connect must not leak the first FD
      end if;
      Locate (Node, N_Len, Found);
      if not Found then
         return;
      end if;
      declare
         P : Interfaces.C.Strings.chars_ptr := Interfaces.C.Strings.New_String (Node (1 .. N_Len));
      begin
         FD := C_Open (P, O_RDWR);
         Interfaces.C.Strings.Free (P);
      end;
      if FD < 0 then
         return;                             --  usually: no udev rule
      end if;
      --  Detach any kernel driver, then claim the CCID interface.
      declare
         D : aliased Usbfs_Ioctl := (Ifno => int (Iface), Ioctl_Code => USBDEVFS_DISCONNECT, Data => System.Null_Address);
         I : aliased unsigned := Iface;
      begin
         R := C_Ioctl (FD, USBDEVFS_IOCTL, D'Address);   --  may fail: fine
         R := C_Ioctl (FD, USBDEVFS_CLAIMINTERFACE, I'Address);
         if R /= 0 then
            R := C_Close (FD);
            FD := -1;
            return;
         end if;
      end;
      Connected := True;
      CCID.Power_On (Card, ATR, ATR_Len, X_OK);
      if not X_OK then
         Disconnect;
         return;
      end if;
      declare
         S : constant String := Node (1 .. N_Len) & " if" & Iface'Image & " ATR" & ATR_Len'Image & "B";
      begin
         Info_Len := Natural'Min (S'Length, Info'Length);
         Info (Info'First .. Info'First + Info_Len - 1) := S (S'First .. S'First + Info_Len - 1);
      end;
      OK := True;
   end Connect;

   procedure Transmit
     (Cmd      : in     Bytes;
      Resp     :    out Bytes;
      Resp_Len :    out Index;
      OK       :    out Boolean)
   is
      Data  : Bytes (0 .. CCID.Max_Payload - 1);
      D_Len : Index;
      X_OK  : Boolean;
      Cmd0  : Bytes (0 .. Cmd'Length - 1) := Cmd;   --  CCID wants 'First = 0
   begin
      Resp := (others => 0);
      Resp_Len := 0;
      OK := False;
      if not Connected or else Cmd'Length = 0 or else Cmd'Length > CCID.Max_Payload then
         Cmd0 := (others => 0);
         pragma Inspection_Point (Cmd0);
         return;
      end if;
      CCID.Transfer (Card, Cmd0, Data, D_Len, X_OK);
      Cmd0 := (others => 0);          --  may hold the PIN
      pragma Inspection_Point (Cmd0);
      if not X_OK or else D_Len < 2 or else D_Len > Resp'Length then
         return;
      end if;
      Resp (Resp'First .. Resp'First + D_Len - 1) := Data (0 .. D_Len - 1);
      Resp_Len := D_Len;
      OK := True;
   end Transmit;

   procedure Disconnect is
      R : int;
      I : aliased unsigned := Iface;
      pragma Unreferenced (R);
   begin
      if Connected then
         R := C_Ioctl (FD, USBDEVFS_RELEASEINTERFACE, I'Address);
         R := C_Close (FD);
         FD := -1;
         Connected := False;
      end if;
   end Disconnect;

end PIV.Linux_USB;
