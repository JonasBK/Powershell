function Get-X509IssuerSerialNumberFormat {
  <# Example usage
  $IssuerDistinguishedName = "CN=CONTOSO-DC-CA,DC=contoso,DC=com"
  $SerialNumber = "2B0000000011AC0000000012"
  Get-X509IssuerSerialNumberFormat -SerialNumber $SerialNumber -IssuerDistinguishedName $IssuerDistinguishedName
  #>
  param (
        [string]$SerialNumber,
        [string]$IssuerDistinguishedName
    )

    # Reverse the serial number
    $reversedSerialNumber = $SerialNumber -split "(..)"
    [array]::Reverse($reversedSerialNumber)
    $reversedSerialNumber = $reversedSerialNumber -join ''

    # Split the issuer distinguished name into components and reverse them
    $reversedIssuerComponents = $IssuerDistinguishedName -split ','
    [array]::Reverse($reversedIssuerComponents)
    $reversedIssuerComponents = $reversedIssuerComponents -join ','

    # Format X509IssuerSerialNumber for altSecurityIdentities attribute
    return "X509:<I>{0}<SR>{1}" -f $reversedIssuerComponents, $reversedSerialNumber
}
