program delphi_isvirt;

//
// Delphi
// DELPHI_IS_VIRT
// v 0.2, 17.11.2023
// https://github.com/dkxce/Detect-Virtual-Machine
// en,ru,1251,utf-8
//

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,  ActiveX,  ComObj,  Windows,  Registry,  Variants;

function IsVirtual: boolean;
const
  WbemUser            ='';
  WbemPassword        ='';
  WbemComputer        ='localhost';
  wbemFlagForwardOnly = $00000020;
var
  FSWbemLocator : OLEVariant;
  FWMIService   : OLEVariant;
  FWbemObjectSet: OLEVariant;
  FWbemObject   : OLEVariant;
  oEnum         : IEnumvariant;
  iValue        : LongWord;
  handle        : THandle;
  reg           : TRegistry;

  manufacturer  : string;
  model         : string;
  processor     : string;
  baseboard     : string;
  bios_sn       : string;
  disk_model    : string;
  disk_device   : string;
  pnp_device    : string;
  service       : string;
begin;

  result := False;

  try
    handle := CreateFile('\\.\VBoxMiniRdrDN', GENERIC_READ, FILE_SHARE_READ, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if handle <> $FFFFFFFF then begin
      CloseHandle(handle);
      result := true;
    end;
  except end;
  if result then exit;


  try
    reg := TRegistry.Create(KEY_READ);
    reg.RootKey := HKEY_LOCAL_MACHINE;
    if reg.KeyExists('SOFTWARE\VMware, Inc.\VMware Tools') then result := true;
    reg.Free;
  except end;
  if result then exit;

  try
    FSWbemLocator := CreateOleObject('WbemScripting.SWbemLocator');
    FWMIService   := FSWbemLocator.ConnectServer(WbemComputer, 'root\CIMV2', WbemUser, WbemPassword);

    if not result then try
      // Win32_ComputerSystem
      FWbemObjectSet:= FWMIService.ExecQuery('SELECT * FROM Win32_ComputerSystem','WQL',wbemFlagForwardOnly);
      oEnum         := IUnknown(FWbemObjectSet._NewEnum) as IEnumVariant;
      while oEnum.Next(1, FWbemObject, iValue) = 0 do
      begin
        manufacturer := ''; model := '';
        try
          manufacturer := UpperCase(String(FWbemObject.Manufacturer));
        except end;
        try
          model := UpperCase(String(FWbemObject.Model));
        except end;
        // Hyper-V
        if (manufacturer.Contains('MICROSOFT') and model.Contains('VIRTUAL')) then result := true;
        // VMWare
        if (manufacturer.Contains('VMWARE')) then result := true;
        // VirtualBox
        if (model = 'VIRTUALBOX') then result := true;
        if (model = 'VIRTUAL MACHINE') then result := true;
        // WMWare
        if (model.StartsWith('VMWARE')) then result := true;
        FWbemObject:=Unassigned;
      end;
    except end;

    if not result then try
      // Win32_processor
      FWbemObjectSet:= FWMIService.ExecQuery('SELECT * FROM Win32_processor','WQL',wbemFlagForwardOnly);
      oEnum         := IUnknown(FWbemObjectSet._NewEnum) as IEnumVariant;
      while oEnum.Next(1, FWbemObject, iValue) = 0 do
      begin
        processor := '';
        try
          processor := UpperCase(String(FWbemObject.Manufacturer));
        except end;
        // VBox
        if (processor.Contains('VBOXVBOXVBOX')) then result := true;
        // VMWare
        if (processor.Contains('VMWAREVMWARE')) then result := true;
        // Hyper-V
        if (processor.Contains('PRL HYPERV')) then result := true;
        FWbemObject:=Unassigned;
      end;
    except end;

    if not result then try
      // Win32_BaseBoard
      FWbemObjectSet:= FWMIService.ExecQuery('SELECT * FROM Win32_BaseBoard','WQL',wbemFlagForwardOnly);
      oEnum         := IUnknown(FWbemObjectSet._NewEnum) as IEnumVariant;
      while oEnum.Next(1, FWbemObject, iValue) = 0 do
      begin
        baseboard := '';
        try
          baseboard := UpperCase(String(FWbemObject.Manufacturer));
        except end;
        // Hyper-V
        if (baseboard = 'MICROSOFT CORPORATION') then result := true;
        FWbemObject:=Unassigned;
      end;
    except end;

    if not result then try
      // Win32_BIOS
      FWbemObjectSet:= FWMIService.ExecQuery('SELECT * FROM Win32_BIOS','WQL',wbemFlagForwardOnly);
      oEnum         := IUnknown(FWbemObjectSet._NewEnum) as IEnumVariant;
      while oEnum.Next(1, FWbemObject, iValue) = 0 do
      begin
        bios_sn := '';
        try
          bios_sn := UpperCase(String(FWbemObject.SerialNumber));
        except end;
        // Hyper-V
        if (bios_sn.Contains('VMWARE')) then result := true;
        FWbemObject:=Unassigned;
      end;
    except end;

    if not result then try
      // Win32_DiskDrive
      FWbemObjectSet:= FWMIService.ExecQuery('SELECT * FROM Win32_DiskDrive','WQL',wbemFlagForwardOnly);
      oEnum         := IUnknown(FWbemObjectSet._NewEnum) as IEnumVariant;
      while oEnum.Next(1, FWbemObject, iValue) = 0 do
      begin
        disk_model := ''; disk_device := '';
        try
          disk_model := UpperCase(String(FWbemObject.Model));
        except end;
        try
          disk_device := UpperCase(String(FWbemObject.PNPDeviceID));
        except end;
        // Hyper-V
        if (disk_model.Contains('VIRTUAL'))  then result := true;
        // VMWARE / VEN_VMWARE
        if (disk_model.Contains('VMWARE'))  then result := true;
        // VMWARE / VEN_VMWARE
        if (disk_device.Contains('VEN_VMWARE')) then result := true;
        // QEmu
        if (disk_model.Contains('QEMU')) then result := true;
        // VBox / VBOX_HARDDISK
        if (disk_model.Contains('VBOX')) then result := true;
        // VBox / VBOX_HARDDISK
        if (disk_device.Contains('VBOX_HARDDISK')) then result := true;
        FWbemObject:=Unassigned;
      end;
    except end;

    if not result then try
      // Win32_PnPEntity
      FWbemObjectSet:= FWMIService.ExecQuery('SELECT * FROM Win32_PnPEntity','WQL',wbemFlagForwardOnly);
      oEnum         := IUnknown(FWbemObjectSet._NewEnum) as IEnumVariant;
      while oEnum.Next(1, FWbemObject, iValue) = 0 do
      begin
        pnp_device := '';
        try
          pnp_device := UpperCase(String(FWbemObject.Name));
        except end;
        // VMWare
        if (pnp_device = 'VMWARE POINTING DEVICE') then result := true;
        if (pnp_device = 'VMWARE USB POINTING DEVICE') then result := true;
        if (pnp_device = 'VMWARE VMCU BUS DEVICE') then result := true;
        if (pnp_device = 'VMWARE VIRTUAL S SCSI DISK DEVICE') then result := true;
        if (pnp_device.Contains('VMWARE SATA')) then result := true;
        if (pnp_device.StartsWith('VMWARE SVGA')) then result := true;
        // Virtual Box
        if (pnp_device.Contains('VBOX')) then result := true;
        FWbemObject:=Unassigned;
      end;
    except end;

    if not result then try
      // Win32_Service
      FWbemObjectSet:= FWMIService.ExecQuery('SELECT * FROM Win32_Service','WQL',wbemFlagForwardOnly);
      oEnum         := IUnknown(FWbemObjectSet._NewEnum) as IEnumVariant;
      while oEnum.Next(1, FWbemObject, iValue) = 0 do
      begin
        service := '';
        try
          service := UpperCase(String(FWbemObject.Name));
        except end;
        // VMWare
        if (service = 'WMTOOLS') then result := true;
        if (service = 'TPVCGATEWAY') then result := true;
        if (service = 'TPAUTOCONNSVC') then result := true;
        // Virtual PC
        if (service.Contains('VPCMAP')) then result := true;
        if (service.Contains('WMSRVC')) then result := true;
        if (service.Contains('VMUSRVC')) then result := true;
        // VBox
        if (service.Contains('VBOXSERVICE')) then result := true;
        FWbemObject:=Unassigned;
      end;
    except end;
  except end;

end;


var isVirt : boolean = False;
begin
  try
     CoInitialize(nil);
     try
       isVirt := IsVirtual();
     finally
       CoUninitialize;
     end;
     if (isVirt) then Writeln('9 YES, Machine is Virtual')
     else Writeln('0 NO, Machine is Phisical');
     if (isVirt) then ExitCode := 9
     else ExitCode := 0;
  except
    on E:EOleException do Writeln(Format('EOleException %s %x', [E.Message,E.ErrorCode]));
    on E:Exception do Writeln(E.Classname, ':', E.Message);
  end;
end.
