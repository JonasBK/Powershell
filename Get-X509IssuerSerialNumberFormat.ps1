function Get-X509IssuerSerialNumberFormat {
  <# Example usage
  $issuerDistinguishedName = "CN=CONTOSO-DC-CA,DC=contoso,DC=com"
  $serialNumber = "2B0000000011AC0000000012"
  Get-X509IssuerSerialNumberFormat -serialNumber $serialNumber -issuerDistinguishedName $issuerDistinguishedName
  #>
  param (
        [string]$serialNumber,
        [string]$issuerDistinguishedName
    )

    # Reverse the serial number
    $reversedSerialNumber = $serialNumber -split "(..)"
    [array]::Reverse($reversedSerialNumber)
    $reversedSerialNumber = $reversedSerialNumber -join ''

    # Split the issuer distinguished name into components and reverse them
    $reversedIssuerComponents = $issuerDistinguishedName -split ','
    [array]::Reverse($reversedIssuerComponents)
    $reversedIssuerComponents = $reversedIssuerComponents -join ','

    # Format X509IssuerSerialNumber for altSecurityIdentities attribute
    return "X509:<I>{0}<SR>{1}" -f $reversedIssuerComponents, $reversedSerialNumber
}
