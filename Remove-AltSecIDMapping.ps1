function Remove-AltSecIDMapping {
  <# Example usage
    Remove-AltSecIDMapping -DistinguishedName "CN=Administrator,CN=Users,DC=dumpster,DC=fire" -MappingString "X509:<S>CN=Andy"
  #>
  param (
        [string]$DistinguishedName,
        [string]$MappingString
    )

    $target = [ADSI]"LDAP://$DistinguishedName"
    $value = $target.Properties["altSecurityIdentities"].Value
    $value = $value | Where-Object { $_ –ne $MappingString }
    $target.Properties["altSecurityIdentities"].Value = $value
    $target.CommitChanges()
}
