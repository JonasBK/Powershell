function Add-AltSecIDMapping {
  <# Example usage
    Add-AltSecIDMapping -DistinguishedName "CN=Administrator,CN=Users,DC=dumpster,DC=fire" -MappingString "X509:<S>CN=Andy"
  #>
  param (
        [string]$DistinguishedName,
        [string]$MappingString
    )

    $target = [ADSI]"LDAP://$DistinguishedName"
    $value = $target.Properties["altSecurityIdentities"].Value
    if ($value -eq $null) {
        $value = @($MappingString)
    }
    elseif ($value -is [string]) {
        $value = @($value, $MappingString)
    }
    elseif ($value -is [array]) {
        $value += $MappingString
    }
    $target.Properties["altSecurityIdentities"].Value = $value
    $target.CommitChanges()
}
