# Certificate logon
# Schannel logon (not ntlm or kerberos). Is it "just" LDAP? What more exist?
# https://en.wikipedia.org/wiki/Security_Support_Provider_Interface

Function Get-RemoteLoginInfo 
{
<#
.Synopsis
    The short function description.

.Description
	The long function description

.Example
	C:\PS>Function-Name -param "Param Value"
	
	This example does something

.Example
	C:\PS>
    
	You can have multiple examples

.Notes
	Name: Function-Name
	Author: Author Name
	Last Edit: Date
	Keywords: Any keywords

.Link
    http://foo.com
    http://twitter.com/foo

.Inputs
	None

.Outputs
	None

#Requires -Version 2.0
#>
[CmdletBinding(SupportsShouldProcess=$True)]
	Param
    (
#        [Parameter(Mandatory=$true,HelpMessage="Enter a help message")]
#    	[string]$param1,
#        [Parameter(Mandatory=$false)]
#    	[switch]$param2
    )
    BEGIN 
    {
        # Parameters
        $UraFilepath = "$env:temp\UserRights.txt"
        $ErrorActionPreference = "SilentlyContinue"
        $Check = $null
        $Data = @{}
        $LocalAccounts = Get-WMIObject Win32_Account
    }

    PROCESS
    {
        $null = secedit /export /areas USER_RIGHTS /cfg $UraFilepath
        $Check = Test-Path $UraFilepath

        if ($Check -match "False")
        {
            Write-Warning "Something went wrong"
        }
        else
        {            
            foreach ($line in Get-Content $UraFilepath)
            {
                if (($line -match $regex) -and ($line.StartsWith("Se")))
                {
                    $priv, $principals = $line -split " = "
                    $principals = $principals -split ","
                    $Array = [System.Collections.ArrayList]@()

                    foreach ($principal in $principals)
                    {
                        $name = $null
                        $sid = $null

                        if ($principal.StartsWith("*S"))
                        {
                            $sid = $principal -replace "\*"

                            # Try to translate SID to display name
                            try
                            {
                                $obj = New-Object System.Security.Principal.SecurityIdentifier($sid)
                                $name = $obj.Translate([System.Security.Principal.NTAccount]).Value
                            }
                            catch
                            {
                            }
                        }
                        elseif ($LocalAccounts.Name -contains $principal)
                        {
                            $obj = $LocalAccounts | Where-Object { $_.Name -eq $principal }
                            $name = $principal
                            $sid = $obj.SID
                        }
                        elseif ($LocalAccounts.Caption -contains $principal)
                        {
                            $obj = $LocalAccounts | Where-Object { $_.Caption -eq $principal }
                            $name = $principal
                            $sid = $obj.SID
                        }
                        elseif ($principal)
                        {
                            $name = $principal
                        }
                    }
                    $null = $Array.Add([PSCustomObject]@{
                        Name = $name
                        SID  = $sid
                    })                    
                }
                $Data.Add($priv, $Array)
            }

            # Get listening ports
            $openPorts = Get-NetTCPConnection | Where-Object { ($_.State -eq "Listen") -and ($_.LocalAddress -ne "127.0.0.1")} `
                | Select-Object -ExpandProperty LocalPort | Sort-Object -Unique
            $Data.Add("OpenPorts", $openPorts)

            # Get running services
            $runningServices = Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object -ExpandProperty Name
            $Data.Add("RunningServices", $runningServices)

            # Check SMB
            $smb = Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature, RejectUnencryptedAccess
            $Data.Add("SMBv1", $smb.EnableSMB1Protocol)
            $Data.Add("SMBv2/3", $smb.EnableSMB2Protocol)
            $Data.Add("SMBRequireSigning", $smb.RequireSecuritySignature)            # Signing is supported in all versions
            $Data.Add("SMBRejectUnencrypted", $smb.RejectUnencryptedAccess)          # Encryption is only supported in SMBv3

            # Check NTLM
            $NTLMRegPath = "HKLM:SYSTEM\CurrentControlSet\Control\Lsa"
            
            # NTLM Denied accounts
            $NTLMDeniedAccounts = @()
            if ((Get-Item -LiteralPath "$NTLMRegPath\MSV1_0").GetValue("RestrictReceivingNTLMTraffic", $null) -ne $null)
            {
                $val = (Get-ItemProperty -Path "$NTLMRegPath\MSV1_0" -Name RestrictReceivingNTLMTraffic).RestrictReceivingNTLMTraffic
                if ($val -eq "1")
                {
                    $NTLMDeniedAccounts = @("DomainAccounts")
                } 
                elseif ($val -eq "2")
                {
                    $NTLMDeniedAccounts = @("DomainAccounts", "LocalAccounts")
                }
            }
            $Data.Add("NTLMDeniedAccounts", $NTLMDeniedAccounts)

            # NTLM supported versions
            $NTLMSupportedVersions = @("LM", "NTLMv1", "NTLMv2")
            if ((Get-Item -LiteralPath $NTLMRegPath).GetValue("LmCompatibilityLevel", $null) -ne $null)
            {
                $val = (Get-ItemProperty -Path $NTLMRegPath -Name LmCompatibilityLevel).LmCompatibilityLevel
                if ($val -eq "4")
                {
                    $NTLMSupportedVersions = @("NTLMv1", "NTLMv2")
                } 
                elseif ($val -eq "5")
                {
                    $NTLMSupportedVersions = @("NTLMv2")
                }
            }
            $Data.Add("NTLMSupportedVersions", $NTLMSupportedVersions)

            # NTLM SSP security requirements
            $NTLMSSPSecurityRequirements = @("128BitEncrypt")
            if ((Get-Item -LiteralPath "$NTLMRegPath\MSV1_0").GetValue("NTLMMinServerSec", $null) -ne $null)
            {
                $val = (Get-ItemProperty -Path "$NTLMRegPath\MSV1_0" -Name NTLMMinServerSec).NTLMMinServerSec
                if ($val -eq "0")
                {
                    $NTLMSSPSecurityRequirements = @()
                } 
                elseif ($val -eq "524288")
                {
                    $NTLMSSPSecurityRequirements = @("NTLMv2Signing")
                }
                elseif ($val -eq "537395200")
                {
                    $NTLMSSPSecurityRequirements = @("128BitEncrypt", "NTLMv2Signing")
                }
            }
            $Data.Add("NTLMSSPSecurityRequirements", $NTLMSecurityRequirements)

            # Kerberos encryption types
            $KerberosEncryptionTypes = [System.Collections.ArrayList]@("RC4_HMAC_MD5", "AES128_HMAC_SHA1", "AES256_HMAC_SHA1", "Future")
            if ((Get-Item -LiteralPath "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters").GetValue("SupportedEncryptionTypes", $null) -ne $null)
            {
                $KerberosEncryptionTypes = [System.Collections.ArrayList]@()
                $val = (Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name SupportedEncryptionTypes).SupportedEncryptionTypes
                $valBin = ([string]([convert]::ToString($val,2))).PadLeft(31,'0')
                if ($valBin[0] -eq "1")
                {
                    $null = $KerberosEncryptionTypes.Add("DES_CBC_CRC")
                }
                if ($valBin[1] -eq "1")
                {
                    $null = $KerberosEncryptionTypes.Add("DES_CBC_MD5")
                }
                if ($valBin[2] -eq "1")
                {
                    $null = $KerberosEncryptionTypes.Add("RC4_HMAC_MD5")
                }
                if ($valBin[3] -eq "1")
                {
                    $null = $KerberosEncryptionTypes.Add("AES128_HMAC_SHA1")
                }
                if ($valBin[4] -eq "1")
                {
                    $null = $KerberosEncryptionTypes.Add("AES256_HMAC_SHA1")
                }
                if (-not $valBin.Substring(0, 26).Contains("0"))
                {
                    $null = $KerberosEncryptionTypes.Add("Future")
                }
            }
            $Data.Add("KerberosEncryptionTypes", $KerberosEncryptionTypes)

            # Smart card or WHfB required for interactive logon
            $SmartCardRequired = $false
            if ((Get-Item -LiteralPath "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").GetValue("scforceoption", $null) -ne $null)
            {
                $val = (Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name scforceoption).scforceoption
                if ($val -eq "1")
                {
                    $SmartCardRequired = $true
                } 
            }
            $Data.Add("SmartCardRequired", $SmartCardRequired)


            #ssh sshd
            # https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_server_configuration#windows-configurations-in-sshd_config

            # Fuck pku2u: https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-allow-pku2u-authentication-requests-to-this-computer-to-use-online-identities
            # Remote registry?
            
            # PSRemote priv
            $aces = (Get-PSSessionConfiguration -Name Microsoft.PowerShell).SecurityDescriptorSddl | ConvertFrom-SddlString | Select-Object -ExpandProperty DiscretionaryAcl
            # Which permissions do you need? (GenericAll, GenericExecute, GenericRead, GenericWrite)
            
            # BUILTIN\Guests: AccessDenied (GenericAll, GenericExecute, GenericRead, GenericWrite)
            # NT AUTHORITY\INTERACTIVE: AccessAllowed (GenericAll)
            # BUILTIN\Administrators: AccessAllowed (GenericAll)
            # BUILTIN\Remote Management Users: AccessAllowed (GenericAll)

            # WMI

            # DCOM
            # Security options:
                # https://www.windows-security.org/a11dfb1a8d30a01e8fe206c55aafc38a/dcom-machine-access-restrictions-in-security-descriptor-definition
                # https://www.windows-security.org/7f7dbf98491c563ff269bec77aa6c063/dcom-machine-launch-restrictions-in-security-descriptor-definition 
            
        }
    }
} #End function


