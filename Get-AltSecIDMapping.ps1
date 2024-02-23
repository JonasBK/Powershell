function Get-AltSecIDMapping {
  <# Example usage
    Get-AltSecIDMapping -DistinguishedName "CN=Administrator,CN=Users,DC=dumpster,DC=fire"
    
    <Output:>
    X509:<S>DC=fire,DC=dumpster,CN=Users,CN=Andy3
    X509:<S>DC=fire,DC=dumpster,CN=Users,CN=Andy2
    X509:<S>DC=fire,DC=dumpster,CN=Users,CN=Andy
  #>
  param (
        [string]$DistinguishedName
    )

    $target = [ADSI]"LDAP://$DistinguishedName"
    $value = $target.Properties["altSecurityIdentities"].Value
    $value | ForEach-Object { Write-Host $_ }
}
