<#
.SYNOPSIS
Temporarily enables Windows client 802.1X diagnostic event logs, then restores their settings.
.DESCRIPTION
Run elevated in Windows PowerShell 5.1. Saves the original enabled states and log sizes
in a private machine- and caller-bound baseline under ProgramData\Dot1xLogging.
The collector remains read-only. This helper never clears logs, changes authentication
or TLS policy, reboots, or restarts services. Dot-sourcing imports functions only.
.PARAMETER Enable
Enable installed allowlisted client channels and raise sizes below 100 MiB to 100 MiB.
Repeated Enable uses the original baseline, not the currently enabled settings.
.PARAMETER Restore
Restore original enabled states, sizes, and optional Schannel value. On any failure,
keep the baseline and rerun Restore with the same elevated account on the same machine.
.PARAMETER OutputDirectory
With Enable, place a new private EapHost trace folder under this report parent.
The default is Dot1x-Report in the current directory. Restore uses the saved path.
.PARAMETER EventsOnly
With Enable, prepare event channels and optional Schannel logging only.
.PARAMETER IncludeSchannel
With Enable, also save the Schannel EventLogging DWORD (or its absence) and set it to 7.
A reboot is required to apply Schannel changes, including restoration. No reboot is run.
.EXAMPLE
.\Set-8021xLogging.ps1 -Enable
.EXAMPLE
.\Set-8021xLogging.ps1 -Restore
#>
#requires -Version 5.1
[CmdletBinding(DefaultParameterSetName='Enable')]
param(
    [Parameter(ParameterSetName='Enable')][switch]$Enable,
    [Parameter(ParameterSetName='Restore')][switch]$Restore,
    [Parameter(ParameterSetName='Enable')][switch]$IncludeSchannel,
    [Parameter(ParameterSetName='Enable')][string]$OutputDirectory,
    [Parameter(ParameterSetName='Enable')][switch]$EventsOnly
)

function Get-LoggingCoreChannels {
    @('WLAN-AutoConfig','Wired-AutoConfig','EapHost','CAPI2','NTLM') | ForEach-Object { 'Microsoft-Windows-' + $_ + '/Operational' }
}

function Test-LoggingChannel {
    param([string]$Name)
    if ((Get-LoggingCoreChannels) -contains $Name) { return $true }
    if ($Name -cmatch '^Microsoft-Windows-(OneX|EapMethods-(RasChap|RasTls|Sim|Ttls))/Operational$') { return $true }
    return $Name -cmatch '^Microsoft-Windows-(Dhcp-Client|Dhcpv6-Client|DNS-Client|NetworkProfile|GroupPolicy|DeviceManagement-Enterprise-Diagnostics-Provider|CertificateServicesClient-[A-Za-z0-9-]+)/(Admin|Operational)$'
}

function Invoke-LoggingNative {
    param([string[]]$Arguments)
    $exe = [IO.Path]::Combine([Environment]::GetFolderPath('Windows'),'System32\wevtutil.exe')
    # PowerShell 5.1 can turn redirected native stderr into ErrorRecord objects.
    $oldPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $global:LASTEXITCODE = $null
        $text = @(& $exe @Arguments 2>&1)
        $code = $global:LASTEXITCODE
        [pscustomobject]@{ ExitCode=$code; Text=($text -join "`n") }
    } finally { $ErrorActionPreference = $oldPreference }
}

function Invoke-LoggingWevtutil {
    param([string[]]$Arguments)
    $result = Invoke-LoggingNative $Arguments
    if ($result.ExitCode -ne 0 -or $null -eq $result.ExitCode) {
        $detail = [string]$result.Text
        if ($detail.Length -gt 1024) { $detail = $detail.Substring(0,1024) + ' [truncated]' }
        throw "wevtutil $($Arguments -join ' ') failed (exit=$($result.ExitCode)): $detail"
    }
    return $result.Text
}

function Get-LoggingInstalledChannels {
    @((Invoke-LoggingWevtutil @('el')) -split '[\r\n]+' | Where-Object { $_ })
}

function Get-LoggingChannelSettings {
    param([string]$Name)
    if (-not (Test-LoggingChannel $Name)) { throw 'Channel is outside the client allowlist.' }
    $text = Invoke-LoggingWevtutil @('gl',$Name,'/f:xml')
    $settings = New-Object Xml.XmlReaderSettings
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit; $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 65536
    $reader = [Xml.XmlReader]::Create((New-Object IO.StringReader($text)), $settings)
    try {
        $xml = New-Object Xml.XmlDocument; $xml.XmlResolver = $null; $xml.Load($reader)
        $root = $xml.DocumentElement
        if ($root.LocalName -ne 'channel' -or $root.GetAttribute('name') -cne $Name -or $root.GetAttribute('enabled') -cnotmatch '^(true|false)$') { throw 'Unexpected channel configuration XML.' }
        $sizes = @($root.SelectNodes('./*[local-name()="logging"]/*[local-name()="maxSize"]'))
        if ($sizes.Count -ne 1 -or $sizes[0].InnerText -notmatch '^[0-9]+$') { throw 'Unexpected channel size XML.' }
        $size = [long]::Parse($sizes[0].InnerText, [Globalization.CultureInfo]::InvariantCulture)
        if ($size -lt 65536) { throw 'Unexpected channel size.' }
        [pscustomobject]@{ Name=$Name; Enabled=($root.GetAttribute('enabled') -ceq 'true'); MaximumSize=$size }
    } finally { $reader.Dispose() }
}

function Set-LoggingChannelSettings {
    param([string]$Name, [bool]$Enabled, [long]$MaximumSize)
    if (-not (Test-LoggingChannel $Name) -or $MaximumSize -lt 65536) { throw 'Invalid channel settings.' }
    $null = Invoke-LoggingWevtutil @('sl',$Name,('/e:' + $Enabled.ToString().ToLowerInvariant()),('/ms:' + $MaximumSize.ToString([Globalization.CultureInfo]::InvariantCulture)))
    $actual = Get-LoggingChannelSettings $Name
    if ($actual.Enabled -ne $Enabled -or $actual.MaximumSize -ne $MaximumSize) { throw "Channel settings did not persist: $Name" }
}

function Get-LoggingSchannel {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL', $false)
    if ($null -eq $key) { throw 'Schannel registry key is unavailable.' }
    try {
        if ($key.GetValueNames() -notcontains 'EventLogging') { return [pscustomobject]@{ Present=$false; Value=$null } }
        if ($key.GetValueKind('EventLogging') -ne [Microsoft.Win32.RegistryValueKind]::DWord) { throw 'Schannel EventLogging is not a DWORD; no changes were made to it.' }
        # Registry DWORDs use signed Int32 in .NET. Preserve all 32 bits in JSON.
        [pscustomobject]@{ Present=$true; Value=([long]$key.GetValue('EventLogging') -band 0xffffffffL) }
    } finally { $key.Dispose() }
}

function Set-LoggingSchannel {
    param($Setting)
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL', $true)
    if ($null -eq $key) { throw 'Schannel registry key is unavailable.' }
    try {
        if ($Setting.Present) {
            $signed = [BitConverter]::ToInt32([BitConverter]::GetBytes([uint32]$Setting.Value),0)
            $key.SetValue('EventLogging',$signed,[Microsoft.Win32.RegistryValueKind]::DWord)
        } else { $key.DeleteValue('EventLogging',$false) }
        $key.Flush()
    } finally { $key.Dispose() }
    $actual = Get-LoggingSchannel
    if ($actual.Present -ne $Setting.Present -or $actual.Value -ne $Setting.Value) { throw 'Schannel EventLogging did not persist.' }
}

function Assert-LoggingProperties {
    param($Object, [string[]]$Names)
    if ($null -eq $Object -or $Object -isnot [pscustomobject]) { throw 'Invalid logging baseline object.' }
    $actual = @($Object.PSObject.Properties.Name | Sort-Object)
    if (($actual -join '|') -cne (($Names | Sort-Object) -join '|')) { throw 'Unexpected logging baseline fields.' }
}

function Test-LoggingInteger {
    param($Value)
    return $Value -is [int] -or $Value -is [long]
}

function Assert-LoggingState {
    param($State, [string]$Machine, [string]$Caller)
    Assert-LoggingProperties $State @('Version','Machine','Caller','Channels','Schannel')
    if (-not (Test-LoggingInteger $State.Version) -or $State.Version -ne 1 -or $State.Machine -cne $Machine -or $State.Caller -cne $Caller) { throw 'Logging baseline version, machine, or caller does not match.' }
    if ($State.Channels -isnot [array] -or $State.Channels.Count -gt 128) { throw 'Invalid baseline channel list.' }
    $seen = @{}
    foreach ($channel in $State.Channels) {
        Assert-LoggingProperties $channel @('Name','Enabled','MaximumSize')
        if ($channel.Name -isnot [string] -or -not (Test-LoggingChannel $channel.Name) -or $seen.ContainsKey($channel.Name) -or $channel.Enabled -isnot [bool] -or -not (Test-LoggingInteger $channel.MaximumSize) -or $channel.MaximumSize -lt 65536) { throw 'Invalid baseline channel settings.' }
        $seen[$channel.Name] = $true
    }
    if ($null -ne $State.Schannel) {
        Assert-LoggingProperties $State.Schannel @('Present','Value')
        if ($State.Schannel.Present -isnot [bool]) { throw 'Invalid Schannel baseline presence.' }
        if ($State.Schannel.Present) {
            if (-not (Test-LoggingInteger $State.Schannel.Value) -or $State.Schannel.Value -lt 0 -or $State.Schannel.Value -gt 4294967295L) { throw 'Invalid Schannel baseline DWORD.' }
        } elseif ($null -ne $State.Schannel.Value) { throw 'An absent Schannel baseline must not have a value.' }
    }
}

function New-LoggingState {
    param([string]$Machine, [string]$Caller, [bool]$Schannel)
    $installed = @(Get-LoggingInstalledChannels)
    $selected = @($installed | Where-Object { Test-LoggingChannel $_ } | Sort-Object -Unique)
    $missing = @((Get-LoggingCoreChannels) | Where-Object { $installed -notcontains $_ })
    if ($missing.Count) { Write-Host ('Not installed; skipped: ' + ($missing -join ', ')) }
    $families = @('OneX','EapMethods-RasChap','EapMethods-RasTls','EapMethods-Sim','EapMethods-Ttls','Dhcp-Client','Dhcpv6-Client','DNS-Client','NetworkProfile','GroupPolicy','DeviceManagement-Enterprise-Diagnostics-Provider','CertificateServicesClient-*')
    $absent = @($families | Where-Object { $family = $_; @($selected | Where-Object { $_ -like ('Microsoft-Windows-' + $family + '/*') }).Count -eq 0 })
    if ($absent.Count) { Write-Host ('Optional client families not installed; skipped: ' + ($absent -join ', ')) }
    $channels = @($selected | ForEach-Object { Get-LoggingChannelSettings $_ })
    $tls = $null
    if ($Schannel) { $tls = Get-LoggingSchannel }
    $state = [pscustomobject]@{ Version=1; Machine=$Machine; Caller=$Caller; Channels=$channels; Schannel=$tls }
    Assert-LoggingState $state $Machine $Caller
    return $state
}

function Invoke-LoggingChanges {
    param($State, [bool]$Restoring)
    $failures = @(); $done = 0
    foreach ($channel in $State.Channels) {
        try {
            $enabled = $channel.Enabled; $size = $channel.MaximumSize
            if (-not $Restoring) {
                # Do not shrink a log that somebody enlarged after the baseline was saved.
                $current = Get-LoggingChannelSettings $channel.Name
                $enabled = $true; $size = [Math]::Max($current.MaximumSize, 104857600L)
            }
            Set-LoggingChannelSettings $channel.Name $enabled $size
            $done++
        } catch { $failures += ($channel.Name + ': ' + $_.Exception.Message) }
    }
    if ($null -ne $State.Schannel) {
        try {
            $setting = $State.Schannel
            if (-not $Restoring) { $setting = [pscustomobject]@{ Present=$true; Value=7L } }
            Set-LoggingSchannel $setting
        } catch { $failures += ('Schannel: ' + $_.Exception.Message) }
        Write-Host 'Schannel EventLogging: reboot required to apply changes, including restoration. No reboot was started.'
    }
    Write-Host ("Client channels configured: $done/$($State.Channels.Count). Logs were not cleared.")
    if ($failures.Count) { throw ("Logging changes incomplete. Baseline retained; rerun -Restore to recover.`n" + ($failures -join "`n")) }
}

function Resolve-LoggingOutputDirectory {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { $Path = Join-Path -Path (Get-Location).Path -ChildPath 'Dot1x-Report' }
    [System.Management.Automation.ProviderInfo]$provider = $null
    [System.Management.Automation.PSDriveInfo]$drive = $null
    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path,[ref]$provider,[ref]$drive)
    if ($provider.Name -ne 'FileSystem') { throw 'Trace output must use the FileSystem provider.' }
    $fullPath = [IO.Path]::GetFullPath($fullPath)
    if ($fullPath -notmatch '^[A-Za-z]:\\' -or $fullPath.Substring(2).Contains(':')) { throw 'Trace output requires a local directory path.' }
    if ($fullPath.Length -gt 3) { $fullPath = $fullPath.TrimEnd('\') }
    return $fullPath
}

function Initialize-LoggingStore {
    if ('Dot1xLoggingV2.Store' -as [type]) { return }
    # Like the collector's private-file path: protected ACLs, pinned non-reparse
    # ancestors, create-new files, and no path-based deletion of an open baseline.
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
namespace Dot1xLoggingV2 {
    [StructLayout(LayoutKind.Sequential)] internal struct SA { public int Size; public IntPtr Descriptor; public int Inherit; }
    [StructLayout(LayoutKind.Sequential)] internal struct Info {
        public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Created,Accessed,Written;
        public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;
    }
    [StructLayout(LayoutKind.Sequential)] internal struct Disposition { [MarshalAs(UnmanagedType.Bool)] public bool Delete; }
    internal static class PrivatePaths {
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle handle,out Info info);
        internal static FileSystemSecurity Security(string sid,bool directory) {
            FileSystemSecurity acl=directory ? (FileSystemSecurity)new DirectorySecurity() : new FileSecurity();
            acl.SetOwner(new SecurityIdentifier(sid)); acl.SetAccessRuleProtection(true,false);
            foreach(string value in new HashSet<string>(new string[]{sid,"S-1-5-18","S-1-5-32-544"})) {
                var inherit=directory ? InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit : InheritanceFlags.None;
                acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(value),FileSystemRights.FullControl,inherit,PropagationFlags.None,AccessControlType.Allow));
            }
            return acl;
        }
        internal static void Validate(FileSystemSecurity acl,string sid,bool directory) {
            var allowed=new HashSet<string>(new string[]{sid,"S-1-5-18","S-1-5-32-544"});
            if(acl.GetOwner(typeof(SecurityIdentifier)).Value!=sid || !acl.AreAccessRulesProtected) throw new IOException("Logging state owner or inheritance is unsafe.");
            foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier))) {
                var inherit=directory ? InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit : InheritanceFlags.None;
                if(!allowed.Remove(rule.IdentityReference.Value) || rule.IsInherited || rule.AccessControlType!=AccessControlType.Allow || rule.FileSystemRights!=FileSystemRights.FullControl || rule.InheritanceFlags!=inherit || rule.PropagationFlags!=PropagationFlags.None) throw new IOException("Logging state ACL is unsafe.");
            }
            if(allowed.Count!=0) throw new IOException("Logging state ACL is incomplete.");
        }
        internal static void ValidateTraceSecurity(FileSystemSecurity acl,string sid) {
            var allowed=new HashSet<string>(new string[]{sid,"S-1-5-18","S-1-5-32-544"});
            var effective=new HashSet<string>();
            if(!allowed.Contains(acl.GetOwner(typeof(SecurityIdentifier)).Value)) throw new IOException("Trace file owner is unsafe.");
            foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier))) {
                string principal=rule.IdentityReference.Value;
                if(!allowed.Contains(principal) || rule.AccessControlType!=AccessControlType.Allow || rule.FileSystemRights!=FileSystemRights.FullControl) throw new IOException("Trace file ACL is unsafe.");
                if((rule.PropagationFlags & PropagationFlags.InheritOnly)==0) effective.Add(principal);
            }
            if(!effective.SetEquals(allowed)) throw new IOException("Trace file ACL is incomplete.");
        }
        internal static void CheckFile(SafeFileHandle handle,bool directory) {
            Info info;
            if(!GetFileInformationByHandle(handle,out info)) throw new Win32Exception(Marshal.GetLastWin32Error(),"Logging state attributes failed");
            if((info.Attributes & 0x400)!=0 || ((info.Attributes & 0x10)!=0)!=directory || (!directory && info.Links!=1)) throw new IOException("Logging state contains a reparse point, hard link, or wrong item type.");
        }
    }
    public sealed class DirectoryLease : IDisposable {
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr sa,uint mode,uint flags,IntPtr template);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateDirectoryW(string path,ref SA sa);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(SafeFileHandle handle,int kind,ref Disposition value,uint size);
        readonly List<SafeFileHandle> directories=new List<SafeFileHandle>();
        bool createdLeaf;
        readonly string sid;
        public string Path { get; private set; }
        public DirectoryLease(string directory,string caller,bool createParents,bool requireNew) : this(directory,caller,createParents,requireNew,requireNew) { }
        internal static DirectoryLease OpenState(string directory,string caller,bool create) { return new DirectoryLease(directory,caller,false,create,false); }
        DirectoryLease(string directory,string caller,bool createParents,bool createLeaf,bool requireNew) {
            string full=System.IO.Path.GetFullPath(directory);
            if(full.Length<4 || full[1]!=':' || full[2]!='\\' || full!=directory || full.EndsWith("\\",StringComparison.Ordinal) || full.IndexOf(':',2)>=0) throw new IOException("Trace output requires a canonical local directory path.");
            if(createParents && !requireNew) throw new ArgumentException("Reopening trace output cannot create directories.");
            Path=full; sid=caller;
            var ancestors=new List<string>();
            for(var d=new DirectoryInfo(full);d!=null;d=d.Parent) ancestors.Add(d.FullName);
            ancestors.Reverse();
            try {
                foreach(string ancestor in ancestors) {
                    bool leaf=ancestor==full;
                    bool created=false;
                    if((leaf && createLeaf) || (!leaf && createParents && ancestor.Length>3)) {
                        byte[] bytes=PrivatePaths.Security(caller,true).GetSecurityDescriptorBinaryForm();
                        GCHandle pinned=GCHandle.Alloc(bytes,GCHandleType.Pinned);
                        try {
                            SA sa=new SA(); sa.Size=Marshal.SizeOf(typeof(SA)); sa.Descriptor=pinned.AddrOfPinnedObject();
                            created=CreateDirectoryW(ancestor,ref sa);
                            if(!created) {
                                int error=Marshal.GetLastWin32Error();
                                if(error!=183 || (leaf && requireNew)) throw new Win32Exception(error,"Private trace directory creation failed: "+ancestor);
                            }
                        } finally { pinned.Free(); }
                    }
                    uint access=(leaf && created && requireNew) ? 0x30080U : 0x20080U;
                    SafeFileHandle handle=CreateFileW(ancestor,access,1,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
                    if(handle.IsInvalid) { int error=Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error,"Trace directory open failed: "+ancestor); }
                    directories.Add(handle); PrivatePaths.CheckFile(handle,true);
                    if(created || leaf) PrivatePaths.Validate(Directory.GetAccessControl(ancestor),caller,true);
                    if(leaf) createdLeaf=created && requireNew;
                }
            } catch { Dispose(); throw; }
        }
        public bool ValidateTraceFile(string fileName,bool allowMissing) { return ValidateTraceFile(fileName,allowMissing,false); }
        public bool ValidateTraceFile(string fileName,bool allowMissing,bool finalized) {
            if(directories.Count==0) throw new ObjectDisposedException("DirectoryLease");
            if(String.IsNullOrEmpty(fileName) || fileName=="." || fileName==".." || fileName.IndexOfAny(System.IO.Path.GetInvalidFileNameChars())>=0) throw new IOException("Trace file must be one local filename.");
            string filePath=System.IO.Path.Combine(Path,fileName);
            using(SafeFileHandle handle=CreateFileW(filePath,0x20080,finalized ? 1U : 3U,IntPtr.Zero,3,0x00200000,IntPtr.Zero)) {
                if(handle.IsInvalid) {
                    int error=Marshal.GetLastWin32Error();
                    if(allowMissing && error==2) return false;
                    throw new Win32Exception(error,"Trace file validation open failed");
                }
                PrivatePaths.CheckFile(handle,false);
                PrivatePaths.ValidateTraceSecurity(File.GetAccessControl(filePath,AccessControlSections.Access|AccessControlSections.Owner),sid);
            }
            return true;
        }
        public void DeleteEmptyDirectory() {
            if(!createdLeaf || directories.Count==0) throw new InvalidOperationException("Only this lease's new empty trace directory can be removed.");
            Disposition value=new Disposition(); value.Delete=true;
            if(!SetFileInformationByHandle(directories[directories.Count-1],4,ref value,4)) throw new Win32Exception(Marshal.GetLastWin32Error(),"Empty trace directory cleanup failed");
            createdLeaf=false;
        }
        public void Dispose() {
            for(int i=directories.Count-1;i>=0;i--) directories[i].Dispose();
            directories.Clear();
        }
    }

    [StructLayout(LayoutKind.Sequential)] internal struct TraceWnode {
        public uint BufferSize,ProviderId;
        public ulong HistoricalContext;
        public long TimeStamp;
        public Guid Guid;
        public uint ClientContext,Flags;
    }
    [StructLayout(LayoutKind.Sequential)] internal struct TraceProperties {
        public TraceWnode Wnode;
        public uint BufferSize,MinimumBuffers,MaximumBuffers,MaximumFileSize,LogFileMode,FlushTimer,EnableFlags;
        public int AgeLimit;
        public uint NumberOfBuffers,FreeBuffers,EventsLost,BuffersWritten,LogBuffersLost,RealTimeBuffersLost;
        public IntPtr LoggerThreadId;
        public uint LogFileNameOffset,LoggerNameOffset;
    }
    public sealed class TraceSnapshot {
        public ulong Handle;
        public Guid SessionGuid;
        public string SessionName,TracePath;
        public uint LogFileMode,MaximumFileSize,EventsLost,LogBuffersLost;
    }
    public static class EapHostTrace {
        static readonly Guid Provider=new Guid("5f31090b-d990-4e91-b16d-46121d0255aa");
        const uint CircularMode=0x10000002,LimitMiB=256,NotFound=4201,GuidNotFound=4200;
        const int StringChars=1025,ProviderInfoLimit=65536;
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern uint StartTraceW(out ulong handle,string name,IntPtr properties);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern uint ControlTraceW(ulong handle,string name,IntPtr properties,uint code);
        [DllImport("advapi32.dll",ExactSpelling=true)] static extern uint EnableTraceEx2(ulong handle,ref Guid provider,uint code,byte level,ulong any,ulong all,uint timeout,IntPtr parameters);
        [DllImport("advapi32.dll",ExactSpelling=true)] static extern uint EnumerateTraceGuidsEx(int kind,ref Guid provider,uint inputSize,IntPtr buffer,uint size,out uint returned);
        static int HeaderSize { get { return Marshal.SizeOf(typeof(TraceProperties)); } }
        static int PropertiesSize { get { return HeaderSize+StringChars*4; } }
        static IntPtr NewProperties(Guid id,string path,bool starting) {
            IntPtr memory=Marshal.AllocHGlobal(PropertiesSize);
            try {
                Marshal.Copy(new byte[PropertiesSize],0,memory,PropertiesSize);
                var p=new TraceProperties();
                p.Wnode.BufferSize=(uint)PropertiesSize; p.Wnode.Guid=id; p.Wnode.Flags=0x20000;
                p.LoggerNameOffset=(uint)HeaderSize; p.LogFileNameOffset=(uint)(HeaderSize+StringChars*2);
                if(starting) {
                    p.Wnode.ClientContext=1; p.BufferSize=64; p.MinimumBuffers=2; p.MaximumBuffers=16;
                    p.MaximumFileSize=LimitMiB; p.LogFileMode=CircularMode; p.FlushTimer=5;
                    byte[] bytes=Encoding.Unicode.GetBytes(path+"\0");
                    if(bytes.Length>StringChars*2) throw new IOException("Trace path exceeds the ETW limit.");
                    Marshal.Copy(bytes,0,IntPtr.Add(memory,(int)p.LogFileNameOffset),bytes.Length);
                }
                Marshal.StructureToPtr(p,memory,false); return memory;
            } catch { Marshal.FreeHGlobal(memory); throw; }
        }
        static string ReadName(IntPtr memory,uint offset) {
            if(offset<(uint)HeaderSize || (offset&1)!=0 || offset>(uint)(PropertiesSize-2)) throw new IOException("ETW returned an invalid string offset.");
            int count=Math.Min(1024,(PropertiesSize-(int)offset)/2);
            for(int i=0;i<=count;i++) {
                if((long)offset+(long)i*2+2>PropertiesSize) break;
                if(Marshal.ReadInt16(memory,(int)offset+i*2)==0) return Marshal.PtrToStringUni(IntPtr.Add(memory,(int)offset),i);
            }
            throw new IOException("ETW returned an unterminated name.");
        }
        static void CheckIdentity(Guid id,string name,string path) {
            if(id==Guid.Empty || name!="Dot1xLogging-EapHost-"+id.ToString("N")) throw new IOException("Trace session identity is invalid.");
            if(String.IsNullOrWhiteSpace(path) || path.Length>1024 || Path.GetFullPath(path)!=path || Path.GetFileName(path)!="EapHost.etl" || new DirectoryInfo(Path.GetDirectoryName(path)).Name!="EapHost-Trace-"+id.ToString("N")) throw new IOException("Trace output identity is invalid.");
        }
        static TraceSnapshot QueryRaw(ulong handle,string name) {
            IntPtr memory=NewProperties(Guid.Empty,null,false);
            try {
                uint code=ControlTraceW(handle,name,memory,0);
                if(code==NotFound) return null;
                if(code!=0) throw new Win32Exception((int)code,"ETW session query failed");
                var p=(TraceProperties)Marshal.PtrToStructure(memory,typeof(TraceProperties));
                if(p.Wnode.BufferSize>(uint)PropertiesSize || p.Wnode.HistoricalContext==0) throw new IOException("ETW returned invalid session properties.");
                return new TraceSnapshot { Handle=p.Wnode.HistoricalContext,SessionGuid=p.Wnode.Guid,SessionName=ReadName(memory,p.LoggerNameOffset),TracePath=ReadName(memory,p.LogFileNameOffset),LogFileMode=p.LogFileMode,MaximumFileSize=p.MaximumFileSize,EventsLost=p.EventsLost,LogBuffersLost=p.LogBuffersLost };
            } finally { Marshal.FreeHGlobal(memory); }
        }
        static TraceSnapshot QueryOwned(Guid id,string name,string path,bool checkSettings) {
            CheckIdentity(id,name,path);
            TraceSnapshot found=QueryRaw(0,name);
            if(found!=null) {
                if(found.SessionGuid!=id || !String.Equals(found.SessionName,name,StringComparison.Ordinal) || !String.Equals(found.TracePath,path,StringComparison.OrdinalIgnoreCase)) throw new IOException("Trace session identity or output differs from the saved intent.");
                if(checkSettings && (found.LogFileMode!=CircularMode || found.MaximumFileSize!=LimitMiB)) throw new IOException("Trace session settings differ from the bounded capture settings.");
            }
            return found;
        }
        public static TraceSnapshot Query(Guid id,string name,string path) { return QueryOwned(id,name,path,true); }
        static bool IsOwnedLogger(ushort logger,TraceSnapshot owned) {
            if(owned==null) return false;
            TraceSnapshot found=QueryRaw(logger,null);
            if(found==null) throw new IOException("An enabled provider session disappeared during inspection; retry trace preparation.");
            return found.Handle==owned.Handle && found.SessionGuid==owned.SessionGuid && String.Equals(found.SessionName,owned.SessionName,StringComparison.Ordinal) && String.Equals(found.TracePath,owned.TracePath,StringComparison.OrdinalIgnoreCase);
        }
        internal static void CheckProvider(Guid provider,TraceSnapshot owned) {
            IntPtr memory=Marshal.AllocHGlobal(ProviderInfoLimit);
            try {
                uint used=0,code=0;
                for(int attempt=0;attempt<3;attempt++) {
                    code=EnumerateTraceGuidsEx(1,ref provider,16,memory,ProviderInfoLimit,out used);
                    if(code!=122) break;
                    if(used>ProviderInfoLimit) throw new IOException("ETW provider metadata exceeds the inspection bound.");
                }
                if(code==GuidNotFound) return;
                if(code!=0) throw new Win32Exception((int)code,"ETW provider enablement query failed");
                if(used<8 || used>ProviderInfoLimit) throw new IOException("ETW provider metadata size is invalid.");
                uint instances=unchecked((uint)Marshal.ReadInt32(memory,0));
                if(instances>4096) throw new IOException("ETW provider instance count is invalid.");
                long position=8;
                for(uint i=0;i<instances;i++) {
                    if(position+16>used) throw new IOException("ETW provider instance is truncated.");
                    uint next=unchecked((uint)Marshal.ReadInt32(memory,(int)position));
                    uint count=unchecked((uint)Marshal.ReadInt32(memory,(int)position+4));
                    long end=position+16+(long)count*32;
                    if(end>used || count>2048) throw new IOException("ETW provider enablement data is truncated.");
                    for(uint j=0;j<count;j++) {
                        int offset=(int)(position+16+(long)j*32);
                        uint enabled=unchecked((uint)Marshal.ReadInt32(memory,offset));
                        if(enabled>1) throw new IOException("ETW provider enablement state is invalid.");
                        ushort logger=unchecked((ushort)Marshal.ReadInt16(memory,offset+6));
                        if(enabled!=0 && !IsOwnedLogger(logger,owned)) throw new IOException("EapHost tracing is already enabled by another session.");
                    }
                    if(i+1<instances) {
                        if(next<16+(long)count*32 || position+next>=used) throw new IOException("ETW provider instance offset is invalid.");
                        position+=next;
                    } else if(next!=0) throw new IOException("ETW provider instance list is incomplete.");
                }
            } finally { Marshal.FreeHGlobal(memory); }
        }
        internal static TraceSnapshot EnsureForProvider(Guid provider,Guid id,string name,string path) {
            TraceSnapshot found=Query(id,name,path);
            CheckProvider(provider,found);
            if(found==null) {
                if(File.Exists(path) || Directory.Exists(path)) throw new IOException("The saved ETL already exists; retain it and allocate a fresh trace intent.");
                IntPtr memory=NewProperties(id,path,true);
                try {
                    ulong handle; uint code=StartTraceW(out handle,name,memory);
                    if(code!=0) throw new Win32Exception((int)code,"ETW session start failed");
                } finally { Marshal.FreeHGlobal(memory); }
                found=Query(id,name,path);
                if(found==null) throw new IOException("The new ETW session is not running.");
                CheckProvider(provider,found);
            }
            uint enabled=EnableTraceEx2(found.Handle,ref provider,1,0,0x4000ffffUL,0,5000,IntPtr.Zero);
            if(enabled!=0) throw new Win32Exception((int)enabled,"EapHost provider enable failed");
            TraceSnapshot verified=Query(id,name,path);
            if(verified==null) throw new IOException("The enabled ETW session is not running.");
            CheckProvider(provider,verified);
            return verified;
        }
        public static TraceSnapshot Ensure(Guid id,string name,string path) { return EnsureForProvider(Provider,id,name,path); }
        public static void Stop(Guid id,string name,string path) {
            TraceSnapshot found=QueryOwned(id,name,path,false);
            if(found==null) return;
            IntPtr memory=NewProperties(id,null,false);
            uint code;
            try { code=ControlTraceW(found.Handle,null,memory,1); }
            finally { Marshal.FreeHGlobal(memory); }
            if(code!=0 && code!=NotFound && code!=234) throw new Win32Exception((int)code,"ETW session stop failed");
            if(QueryOwned(id,name,path,false)!=null) throw new IOException("The owned ETW session is still running; retry Restore.");
        }
    }
    public sealed class Store : IDisposable {
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr sa,uint mode,uint flags,IntPtr template);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(SafeFileHandle handle,int kind,ref Disposition value,uint size);
        readonly string path,tracePath,sid;
        readonly DirectoryLease directoryLease;
        FileStream baseline,traceIntent;
        public Store(string directory,string caller,bool create) {
            path=Path.Combine(directory,"state.json"); tracePath=Path.Combine(directory,"eaphost-trace.json"); sid=caller;
            directoryLease=DirectoryLease.OpenState(directory,caller,create);
        }
        FileSystemSecurity Security(bool directory) { return PrivatePaths.Security(sid,directory); }
        void Validate(FileSystemSecurity acl,bool directory) { PrivatePaths.Validate(acl,sid,directory); }
        static void CheckFile(SafeFileHandle handle,bool directory) { PrivatePaths.CheckFile(handle,directory); }
        FileStream Open(string file,uint mode,IntPtr descriptor) {
            var handle=CreateFileW(file,0xC0030000,0,descriptor,mode,0x00200000,IntPtr.Zero);
            if(handle.IsInvalid) {
                int error=Marshal.GetLastWin32Error(); handle.Dispose();
                if(mode==3 && error==2) return null;
                throw new Win32Exception(error,"Exclusive logging baseline open failed");
            }
            try { CheckFile(handle,false); return new FileStream(handle,FileAccess.ReadWrite); }
            catch { handle.Dispose(); throw; }
        }
        string ReadState(string file,ref FileStream stream) {
            if(stream!=null) throw new InvalidOperationException("Baseline is already open.");
            stream=Open(file,3,IntPtr.Zero);
            if(stream==null) return null;
            Validate(stream.GetAccessControl(),false);
            if(stream.Length<2 || stream.Length>65536) throw new IOException("Logging baseline size is invalid.");
            byte[] bytes=new byte[(int)stream.Length]; int offset=0;
            while(offset<bytes.Length) { int n=stream.Read(bytes,offset,bytes.Length-offset); if(n==0) throw new EndOfStreamException(); offset+=n; }
            return new UTF8Encoding(false,true).GetString(bytes);
        }
        void SaveState(string file,ref FileStream stream,string json) {
            if(stream!=null) throw new IOException("The original logging baseline must not be overwritten.");
            byte[] data=new UTF8Encoding(false,true).GetBytes(json);
            if(data.Length<2 || data.Length>65536) throw new IOException("Logging baseline size is invalid.");
            byte[] security=Security(false).GetSecurityDescriptorBinaryForm();
            GCHandle pinned=GCHandle.Alloc(security,GCHandleType.Pinned); IntPtr raw=IntPtr.Zero;
            try {
                SA sa=new SA(); sa.Size=Marshal.SizeOf(typeof(SA)); sa.Descriptor=pinned.AddrOfPinnedObject();
                raw=Marshal.AllocHGlobal(sa.Size); Marshal.StructureToPtr(sa,raw,false);
                stream=Open(file,1,raw);
                Validate(stream.GetAccessControl(),false);
                stream.Write(data,0,data.Length); stream.Flush(true);
            } catch(Exception failure) {
                // CREATE_NEW limits cleanup to the file created by this call.
                if(stream!=null) {
                    try { DeleteState(ref stream); }
                    catch(Exception cleanup) { throw new IOException("Initial baseline save and owned-file cleanup failed. Retain the recovery files.",new AggregateException(failure,cleanup)); }
                }
                throw;
            } finally { if(raw!=IntPtr.Zero) Marshal.FreeHGlobal(raw); pinned.Free(); }
        }
        static void DeleteState(ref FileStream stream) {
            if(stream==null) throw new InvalidOperationException("No baseline is open.");
            Disposition value=new Disposition(); value.Delete=true;
            if(!SetFileInformationByHandle(stream.SafeFileHandle,4,ref value,4)) throw new Win32Exception(Marshal.GetLastWin32Error(),"Logging baseline cleanup failed");
            stream.Dispose(); stream=null;
        }
        public string Read() { return ReadState(path,ref baseline); }
        public void SaveNew(string json) { SaveState(path,ref baseline,json); }
        public void DeleteBaseline() { DeleteState(ref baseline); }
        public string ReadTrace() { return ReadState(tracePath,ref traceIntent); }
        public void SaveNewTrace(string json) { SaveState(tracePath,ref traceIntent,json); }
        public void DeleteTrace() { DeleteState(ref traceIntent); }
        public void Dispose() {
            if(baseline!=null) { baseline.Dispose(); baseline=null; }
            if(traceIntent!=null) { traceIntent.Dispose(); traceIntent=null; }
            if(directoryLease!=null) directoryLease.Dispose();
        }
    }
}
'@ -ErrorAction Stop
}

function Assert-LoggingTraceState {
    param($State, [string]$Machine, [string]$Caller)
    Assert-LoggingProperties $State @('Version','Machine','Caller','SessionGuid','TracePath')
    $id=[guid]::Empty
    if (-not (Test-LoggingInteger $State.Version) -or $State.Version -ne 1 -or $State.Machine -cne $Machine -or $State.Caller -cne $Caller -or
        $State.SessionGuid -isnot [string] -or -not [guid]::TryParseExact($State.SessionGuid,'D',[ref]$id) -or $id -eq [guid]::Empty -or $State.SessionGuid -cne $id.ToString('D')) { throw 'EapHost trace intent identity does not match.' }
    $path=$State.TracePath
    if ($path -isnot [string] -or $path.Length -gt 1024 -or $path -notmatch '^[A-Za-z]:\\' -or [IO.Path]::GetFullPath($path) -cne $path -or
        [IO.Path]::GetFileName($path) -cne 'EapHost.etl' -or [IO.Path]::GetFileName([IO.Path]::GetDirectoryName($path)) -cne ('EapHost-Trace-'+$id.ToString('N'))) { throw 'EapHost trace intent output path is invalid.' }
}

function New-LoggingTraceLease {
    param([string]$Path, [string]$Caller, [bool]$Create)
    New-Object Dot1xLoggingV2.DirectoryLease($Path,$Caller,$Create,$Create)
}

function Invoke-LoggingTraceNative {
    param([ValidateSet('Query','Ensure','Stop')][string]$Action, $State)
    $id=[guid]$State.SessionGuid
    $name='Dot1xLogging-EapHost-'+$id.ToString('N')
    switch ($Action) {
        'Query' { [Dot1xLoggingV2.EapHostTrace]::Query($id,$name,$State.TracePath) }
        'Ensure' { [Dot1xLoggingV2.EapHostTrace]::Ensure($id,$name,$State.TracePath) }
        'Stop' { [Dot1xLoggingV2.EapHostTrace]::Stop($id,$name,$State.TracePath) }
    }
}

function Invoke-LoggingTraceSession {
    param($Store, [string]$Machine, [string]$Caller, [bool]$Restoring, [string]$OutputDirectory)
    $json=$Store.ReadTrace()
    $state=$null; $lease=$null
    if ($null -ne $json) {
        $state=ConvertFrom-Json -InputObject $json -ErrorAction Stop
        Assert-LoggingTraceState $state $Machine $Caller
    }
    if ($Restoring) {
        if ($null -eq $state) { return $false }
        # Stop is independent of output-directory validation so recovery can
        # release an owned session even if the output path needs attention.
        $null=Invoke-LoggingTraceNative -Action Stop -State $state
        try {
            $lease=New-LoggingTraceLease -Path ([IO.Path]::GetDirectoryName($state.TracePath)) -Caller $Caller -Create $false
            $exists=$lease.ValidateTraceFile('EapHost.etl',$true,$true)
            if ($exists) { Write-Host ('EapHost trace saved: '+$state.TracePath) }
            else { Write-Host ('EapHost trace ended; ETL file absent: '+$state.TracePath) }
        } finally { if ($null -ne $lease) { $lease.Dispose() } }
        return $true
    }
    if ($null -ne $state) {
        $active=Invoke-LoggingTraceNative -Action Query -State $state
        try {
            $lease=New-LoggingTraceLease -Path ([IO.Path]::GetDirectoryName($state.TracePath)) -Caller $Caller -Create $false
            $exists=$lease.ValidateTraceFile('EapHost.etl',$true,($null -eq $active))
            if ($null -eq $active -and $exists) {
                Write-Host ('EapHost trace retained: '+$state.TracePath)
                # A finalized output gets a fresh intent instead of reuse.
                $Store.DeleteTrace(); $state=$null
            } else {
                $null=Invoke-LoggingTraceNative -Action Ensure -State $state
                Write-Host ('EapHost trace active: '+$state.TracePath)
                return $true
            }
        } finally { if ($null -ne $lease) { $lease.Dispose(); $lease=$null } }
    }
    $root=Resolve-LoggingOutputDirectory $OutputDirectory
    $id=[guid]::NewGuid()
    $path=[IO.Path]::Combine($root,('EapHost-Trace-'+$id.ToString('N')))
    $saved=$false
    try {
        $lease=New-LoggingTraceLease -Path $path -Caller $Caller -Create $true
        $state=[pscustomobject]@{Version=1;Machine=$Machine;Caller=$Caller;SessionGuid=$id.ToString('D');TracePath=[IO.Path]::Combine($lease.Path,'EapHost.etl')}
        Assert-LoggingTraceState $state $Machine $Caller
        $Store.SaveNewTrace(($state|ConvertTo-Json -Depth 4 -Compress)); $saved=$true
        $null=Invoke-LoggingTraceNative -Action Ensure -State $state
        Write-Host ('EapHost trace active: '+$state.TracePath)
        return $true
    } finally {
        if ($null -ne $lease) {
            try { if (-not $saved) { $lease.DeleteEmptyDirectory() } }
            finally { $lease.Dispose() }
        }
    }
}

function Invoke-LoggingSession {
    param($Store, [string]$Machine, [string]$Caller, [bool]$Restoring, [bool]$Schannel, [string]$OutputDirectory, [bool]$EventsOnly=$false)
    $failures=@(); $state=$null; $tracePresent=$false
    if (-not $Restoring) {
        $json=$Store.Read()
        if ($null -eq $json) {
            $state=New-LoggingState $Machine $Caller $Schannel
            $Store.SaveNew(($state|ConvertTo-Json -Depth 6 -Compress))
        } else {
            $state=ConvertFrom-Json -InputObject $json -ErrorAction Stop
            Assert-LoggingState $state $Machine $Caller
            if ($Schannel -and $null -eq $state.Schannel) { throw 'The saved baseline excludes Schannel. Run -Restore, then -Enable -IncludeSchannel.' }
            Write-Host 'Using the original logging baseline and channel selection.'
        }
        try { Invoke-LoggingChanges $state $false } catch { $failures+=$_.Exception.Message }
        if (-not $EventsOnly) {
            try { $null=Invoke-LoggingTraceSession $Store $Machine $Caller $false $OutputDirectory }
            catch { $failures+=('EapHost trace: '+$_.Exception.Message) }
        }
    } else {
        try {
            $json=$Store.Read()
            if ($null -ne $json) {
                $state=ConvertFrom-Json -InputObject $json -ErrorAction Stop
                Assert-LoggingState $state $Machine $Caller
                Invoke-LoggingChanges $state $true
            }
        } catch { $failures+=$_.Exception.Message }
        try { $tracePresent=Invoke-LoggingTraceSession $Store $Machine $Caller $true '' }
        catch { $failures+=('EapHost trace: '+$_.Exception.Message) }
    }
    if ($failures.Count) { throw ("Logging changes incomplete. Recovery state retained; rerun -Restore.`n"+($failures -join "`n")) }
    if ($Restoring) {
        if ($tracePresent) { $Store.DeleteTrace() }
        if ($null -ne $state) { $Store.DeleteBaseline() }
        if ($tracePresent -or $null -ne $state) { Write-Host 'Original logging settings restored; recovery state removed.' }
        else { Write-Host 'No saved logging baseline; nothing to restore.' }
    } else { Write-Host 'Logging enabled. Reproduce the issue, collect evidence, then run -Restore.' }
}

function Start-LoggingHelper {
    param([bool]$Enabling, [bool]$Restoring, [bool]$Schannel, [string]$OutputDirectory, [bool]$EventsOnly=$false)
    if ($Enabling -eq $Restoring -or ($Schannel -and -not $Enabling)) { throw 'Specify -Enable or -Restore. Use -IncludeSchannel only with -Enable.' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $caller = $identity.User.Value
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run from an elevated Windows PowerShell window.' }
    } finally { $identity.Dispose() }
    $machineKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    try {
        $key = $machineKey.OpenSubKey('SOFTWARE\Microsoft\Cryptography')
        if ($null -eq $key) { throw 'Machine identity is unavailable.' }
        try { $machine = [string]$key.GetValue('MachineGuid') } finally { $key.Dispose() }
    } finally { $machineKey.Dispose() }
    if ($machine -notmatch '^[0-9a-fA-F-]{36}$') { throw 'Machine identity is invalid.' }
    $directory = [IO.Path]::Combine([Environment]::GetFolderPath('CommonApplicationData'),'Dot1xLogging')
    Write-Host ('Recovery state: ' + [IO.Path]::Combine($directory,'state.json'))
    Initialize-LoggingStore
    $store = $null
    try {
        # Create the private directory for both modes so an absent baseline is an
        # idempotent no-op without an unchecked Test-Path decision.
        $store = New-Object Dot1xLoggingV2.Store($directory,$caller,$true)
        Invoke-LoggingSession $store $machine $caller $Restoring $Schannel $OutputDirectory $EventsOnly
    } finally { if ($null -ne $store) { $store.Dispose() } }
}

if ($MyInvocation.InvocationName -ne '.') {
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version 2.0
    try { Start-LoggingHelper ([bool]$Enable) ([bool]$Restore) ([bool]$IncludeSchannel) $OutputDirectory ([bool]$EventsOnly) }
    catch { Write-Error -Message $_.Exception.Message -ErrorAction Continue; exit 1 }
}
