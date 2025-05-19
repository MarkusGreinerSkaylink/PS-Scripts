<#
Author:			Markus Greiner Skaylink GmbH
Date:			2025-05-13

Purpose of this script is to prepare a given Windows Server for the installation of 
Entra Connect Sync 

It will make sure that TLS 1.2 is active
and it will install RSAT tools

Microsoft recommends that NTLM is disabled on EntraConnect Server. You should use a GPO for this Server (do not disable NTLM globally without good preparation).
The Script does not create this GPO, but it checks the relevant registry keys

https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-install-prerequisites

#>

$workfolder = "$env:SystemDrive\temp"
$logpath = "$workfolder\01-Prepare-EntraConnect.log" #Local log file

#region Functions and classes Definition
Function Get-ADSyncToolsTls12RegValue
{
    [CmdletBinding()]
    Param
    (
        # Registry Path
        [Parameter(Mandatory=$true,
                   Position=0)]
        [string]
        $RegPath,

# Registry Name
        [Parameter(Mandatory=$true,
                   Position=1)]
        [string]
        $RegName
    )
    $regItem = Get-ItemProperty -Path $RegPath -Name $RegName -ErrorAction Ignore
    $output = "" | select Path,Name,Value
    $output.Path = $RegPath
    $output.Name = $RegName

If ($regItem -eq $null)
    {
        $output.Value = "Not Found"
    }
    Else
    {
        $output.Value = $regItem.$RegName
    }
    $output
}
Function Write-Log {
    Param (
        [System.String]$msg,
        [ValidateSet("INFO", "ERROR", "WARNING")]
        [System.String]$msgtype,
        [Parameter(ValueFromPipeline)]
        $InputObject,
        [switch]$Force
    )
    if ($InputObject) {
        $msg = $InputObject | Out-String
    }
    if ($PSBoundParameters.ContainsKey("Force")) {
        Write-Output -InputObject "$(Get-Date -Format ("[yyyy-MM-dd][HH:mm:ss]")) $msgtype $msg" | Out-File $logpath
    }
    else {
        Write-Output -InputObject "$(Get-Date -Format ("[yyyy-MM-dd][HH:mm:ss]")) $msgtype $msg" | Out-File $logpath -Append
    }
}

#endregion
$regSettings = @()
$regKey = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
$regSettings += Get-ADSyncToolsTls12RegValue $regKey 'SystemDefaultTlsVersions'
$regSettings += Get-ADSyncToolsTls12RegValue $regKey 'SchUseStrongCrypto'

$regKey = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
$regSettings += Get-ADSyncToolsTls12RegValue $regKey 'SystemDefaultTlsVersions'
$regSettings += Get-ADSyncToolsTls12RegValue $regKey 'SchUseStrongCrypto'

$regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
$regSettings += Get-ADSyncToolsTls12RegValue $regKey 'Enabled'
$regSettings += Get-ADSyncToolsTls12RegValue $regKey 'DisabledByDefault'

$regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
$regSettings += Get-ADSyncToolsTls12RegValue $regKey 'Enabled'
$regSettings += Get-ADSyncToolsTls12RegValue $regKey 'DisabledByDefault'

$regSettings

If (-Not (Test-Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'))
{
    New-Item 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Force | Out-Null
}
New-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SystemDefaultTlsVersions' -Value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -PropertyType 'DWord' -Force | Out-Null

If (-Not (Test-Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'))
{
    New-Item 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Force | Out-Null
}
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SystemDefaultTlsVersions' -Value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -PropertyType 'DWord' -Force | Out-Null

If (-Not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'))
{
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
}
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null

If (-Not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'))
{
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
}
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null

Write-Host 'TLS 1.2 has been enabled. You must restart the Windows Server for the changes to take affect.' -ForegroundColor Cyan
write-log -msgtype INFO "TLS 1.2 has been enabled"

Write-Log -msgtype INFO "Installing RSAT"
Install-WindowsFeature -Name RSAT-AD-PowerShell, RSAT-ADDS | Write-Log -msgtype INFO

Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force 

# check NTLM Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
$regName = "RestrictSendingNTLMTraffic"
$NTLM = Get-ItemProperty -Path $regPath -Name $regName | Select-Object -ExpandProperty $regName
if ($NTLM -ne 2) {
    write-host -ForegroundColor Red "Sending NTLM is active on this Server. Microsoft recommends to harden this Server and block Outgoing NTLM"
    Write-Log -msgtype WARNING "Sending NTLM is active. This should not be the case on this T0 Server"
}
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
$regName = "RestrictReceivingNTLMTraffic"
$NTLM = Get-ItemProperty -Path $regPath -Name $regName | Select-Object -ExpandProperty $regName
if ($NTLM -ne 1) {
    write-host -ForegroundColor Red "Receiving NTLM is active on this Server. Microsoft recommends to harden this Server and block Incoming NTLM"
    Write-Log -msgtype WARNING "Receiving NTLM is active. This should not be the case on this T0 Server"
}

write-host "After all issues are resolved, you can continue and install Entra Connect"




