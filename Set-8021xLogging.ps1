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
    [Parameter(ParameterSetName='Enable')][switch]$IncludeSchannel
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

function Initialize-LoggingStore {
    if ('Dot1xLogging.Store' -as [type]) { return }
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
namespace Dot1xLogging {
    [StructLayout(LayoutKind.Sequential)] internal struct SA { public int Size; public IntPtr Descriptor; public int Inherit; }
    [StructLayout(LayoutKind.Sequential)] internal struct Info {
        public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Created,Accessed,Written;
        public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;
    }
    [StructLayout(LayoutKind.Sequential)] internal struct Disposition { [MarshalAs(UnmanagedType.Bool)] public bool Delete; }
    public sealed class Store : IDisposable {
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr sa,uint mode,uint flags,IntPtr template);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateDirectoryW(string path,ref SA sa);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle handle,out Info info);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(SafeFileHandle handle,int kind,ref Disposition value,uint size);
        readonly List<SafeFileHandle> directories=new List<SafeFileHandle>();
        readonly string path,sid;
        FileStream baseline;
        public Store(string directory,string caller,bool create) {
            path=Path.Combine(directory,"state.json"); sid=caller;
            string full=Path.GetFullPath(directory);
            if(full.Length<4 || full[1]!=':' || full[2]!='\\' || full!=directory) throw new IOException("State requires a canonical local path.");
            var ancestors=new List<string>();
            for(var d=new DirectoryInfo(full);d!=null;d=d.Parent) ancestors.Add(d.FullName);
            ancestors.Reverse();
            try {
                foreach(string ancestor in ancestors) {
                    if(ancestor==full && create) {
                        byte[] bytes=Security(true).GetSecurityDescriptorBinaryForm();
                        GCHandle pinned=GCHandle.Alloc(bytes,GCHandleType.Pinned);
                        try {
                            SA sa=new SA(); sa.Size=Marshal.SizeOf(typeof(SA)); sa.Descriptor=pinned.AddrOfPinnedObject();
                            if(!CreateDirectoryW(full,ref sa)) {
                                int error=Marshal.GetLastWin32Error();
                                if(error!=183) throw new Win32Exception(error,"Private logging directory creation failed");
                            }
                        } finally { pinned.Free(); }
                    }
                    SafeFileHandle handle=CreateFileW(ancestor,0x20080,1,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
                    if(handle.IsInvalid) { int error=Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error,"Logging directory open failed"); }
                    directories.Add(handle); CheckFile(handle,true);
                }
                Validate(Directory.GetAccessControl(full),true);
            } catch { Dispose(); throw; }
        }
        FileSystemSecurity Security(bool directory) {
            FileSystemSecurity acl=directory ? (FileSystemSecurity)new DirectorySecurity() : new FileSecurity();
            acl.SetOwner(new SecurityIdentifier(sid)); acl.SetAccessRuleProtection(true,false);
            foreach(string value in new HashSet<string>(new string[]{sid,"S-1-5-18","S-1-5-32-544"})) {
                var inherit=directory ? InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit : InheritanceFlags.None;
                acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(value),FileSystemRights.FullControl,inherit,PropagationFlags.None,AccessControlType.Allow));
            }
            return acl;
        }
        void Validate(FileSystemSecurity acl,bool directory) {
            var allowed=new HashSet<string>(new string[]{sid,"S-1-5-18","S-1-5-32-544"});
            if(acl.GetOwner(typeof(SecurityIdentifier)).Value!=sid || !acl.AreAccessRulesProtected) throw new IOException("Logging state owner or inheritance is unsafe.");
            foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier))) {
                var inherit=directory ? InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit : InheritanceFlags.None;
                if(!allowed.Remove(rule.IdentityReference.Value) || rule.IsInherited || rule.AccessControlType!=AccessControlType.Allow || rule.FileSystemRights!=FileSystemRights.FullControl || rule.InheritanceFlags!=inherit || rule.PropagationFlags!=PropagationFlags.None) throw new IOException("Logging state ACL is unsafe.");
            }
            if(allowed.Count!=0) throw new IOException("Logging state ACL is incomplete.");
        }
        static void CheckFile(SafeFileHandle handle,bool directory) {
            Info info;
            if(!GetFileInformationByHandle(handle,out info)) throw new Win32Exception(Marshal.GetLastWin32Error(),"Logging state attributes failed");
            if((info.Attributes & 0x400)!=0 || ((info.Attributes & 0x10)!=0)!=directory || (!directory && info.Links!=1)) throw new IOException("Logging state contains a reparse point, hard link, or wrong item type.");
        }
        FileStream Open(uint mode,IntPtr descriptor) {
            var handle=CreateFileW(path,0xC0030000,0,descriptor,mode,0x00200000,IntPtr.Zero);
            if(handle.IsInvalid) {
                int error=Marshal.GetLastWin32Error(); handle.Dispose();
                if(mode==3 && error==2) return null;
                throw new Win32Exception(error,"Exclusive logging baseline open failed");
            }
            try { CheckFile(handle,false); return new FileStream(handle,FileAccess.ReadWrite); }
            catch { handle.Dispose(); throw; }
        }
        public string Read() {
            if(baseline!=null) throw new InvalidOperationException("Baseline is already open.");
            baseline=Open(3,IntPtr.Zero);
            if(baseline==null) return null;
            Validate(baseline.GetAccessControl(),false);
            if(baseline.Length<2 || baseline.Length>65536) throw new IOException("Logging baseline size is invalid.");
            byte[] bytes=new byte[(int)baseline.Length]; int offset=0;
            while(offset<bytes.Length) { int n=baseline.Read(bytes,offset,bytes.Length-offset); if(n==0) throw new EndOfStreamException(); offset+=n; }
            return new UTF8Encoding(false,true).GetString(bytes);
        }
        public void SaveNew(string json) {
            if(baseline!=null) throw new IOException("The original logging baseline must not be overwritten.");
            byte[] data=new UTF8Encoding(false,true).GetBytes(json);
            if(data.Length<2 || data.Length>65536) throw new IOException("Logging baseline size is invalid.");
            byte[] security=Security(false).GetSecurityDescriptorBinaryForm();
            GCHandle pinned=GCHandle.Alloc(security,GCHandleType.Pinned); IntPtr raw=IntPtr.Zero;
            try {
                SA sa=new SA(); sa.Size=Marshal.SizeOf(typeof(SA)); sa.Descriptor=pinned.AddrOfPinnedObject();
                raw=Marshal.AllocHGlobal(sa.Size); Marshal.StructureToPtr(sa,raw,false);
                baseline=Open(1,raw);
                Validate(baseline.GetAccessControl(),false);
                baseline.Write(data,0,data.Length); baseline.Flush(true);
            } catch(Exception failure) {
                // Open uses CREATE_NEW. Only this invocation's new file can be removed.
                if(baseline!=null) {
                    try { DeleteBaseline(); baseline.Dispose(); baseline=null; }
                    catch(Exception cleanup) {
                        throw new IOException("Initial baseline save and owned-file cleanup failed. No logging settings were changed; retain state.json for recovery.",new AggregateException(failure,cleanup));
                    }
                }
                throw;
            } finally { if(raw!=IntPtr.Zero) Marshal.FreeHGlobal(raw); pinned.Free(); }
        }
        public void DeleteBaseline() {
            if(baseline==null) throw new InvalidOperationException("No baseline is open.");
            Disposition value=new Disposition(); value.Delete=true;
            if(!SetFileInformationByHandle(baseline.SafeFileHandle,4,ref value,4)) throw new Win32Exception(Marshal.GetLastWin32Error(),"Logging baseline cleanup failed");
        }
        public void Dispose() {
            if(baseline!=null) { baseline.Dispose(); baseline=null; }
            for(int i=directories.Count-1;i>=0;i--) directories[i].Dispose();
            directories.Clear();
        }
    }
}
'@ -ErrorAction Stop
}

function Invoke-LoggingSession {
    param($Store, [string]$Machine, [string]$Caller, [bool]$Restoring, [bool]$Schannel)
    $json = $Store.Read()
    if ($null -eq $json) {
        if ($Restoring) { Write-Host 'No saved logging baseline; nothing to restore.'; return }
        $state = New-LoggingState $Machine $Caller $Schannel
        $Store.SaveNew(($state | ConvertTo-Json -Depth 6 -Compress))
    } else {
        $state = ConvertFrom-Json -InputObject $json -ErrorAction Stop
        Assert-LoggingState $state $Machine $Caller
        if (-not $Restoring -and $Schannel -and $null -eq $state.Schannel) { throw 'The saved baseline excludes Schannel. Run -Restore, then -Enable -IncludeSchannel.' }
        if (-not $Restoring) { Write-Host 'Using the original logging baseline and channel selection.' }
    }
    Invoke-LoggingChanges $state $Restoring
    if ($Restoring) { $Store.DeleteBaseline(); Write-Host 'Original logging settings restored; baseline removed.' }
    else { Write-Host 'Logging enabled. Reproduce the issue, collect evidence, then run -Restore.' }
}

function Start-LoggingHelper {
    param([bool]$Enabling, [bool]$Restoring, [bool]$Schannel)
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
        $store = New-Object Dot1xLogging.Store($directory,$caller,$true)
        Invoke-LoggingSession $store $machine $caller $Restoring $Schannel
    } finally { if ($null -ne $store) { $store.Dispose() } }
}

if ($MyInvocation.InvocationName -ne '.') {
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version 2.0
    try { Start-LoggingHelper ([bool]$Enable) ([bool]$Restore) ([bool]$IncludeSchannel) }
    catch { Write-Error -Message $_.Exception.Message -ErrorAction Continue; exit 1 }
}
