$listNullTemplates = $true  # List templates with msPKI-Certificate-Application-Policy set to Null (not set)
$fixNullTemplates  = $false # For templates with msPKI-Certificate-Application-Policy = Null, set msPKI-Certificate-Application-Policy to be the same as pKIExtendedKeyUsage
$reverseV1NullFix  = $false # For version 1 templates, set msPKI-Certificate-Application-Policy to Null

###################
$rootDSE = New-Object DirectoryServices.DirectoryEntry("LDAP://RootDSE")
$templateContainer = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$($rootDSE.configurationNamingContext)"
$searcher = [adsisearcher]""
$searcher.SearchRoot = "LDAP://$templateContainer"
$searcher.Filter = "(objectClass=pKICertificateTemplate)"
$searcher.PropertiesToLoad.AddRange(@("cn", "pKIExtendedKeyUsage", "msPKI-Certificate-Application-Policy", "msPKI-Template-Schema-Version"))

$results = $searcher.FindAll()

if ($listNullTemplates) {
    foreach ($result in $results) {
        if ($result.Properties["msPKI-Certificate-Application-Policy"].Count -eq 0) {
            Write-Host "$($result.Properties["cn"]) has msPKI-Certificate-Application-Policy = Null, and pKIExtendedKeyUsage set to:"
            if ($result.Properties["pKIExtendedKeyUsage"].Count -eq 0) {
                Write-Host "Null"
            } else {
                Write-Host $result.Properties["pKIExtendedKeyUsage"]
            }
            Write-Host ""
        }
    }
}

if ($fixNullTemplates) {
    foreach ($result in $results) {
        if ($result.Properties["msPKI-Certificate-Application-Policy"].Count -eq 0) {
            Write-Host "Setting $($result.Properties["cn"])'s msPKI-Certificate-Application-Policy to:"
            if ($result.Properties["pKIExtendedKeyUsage"].Count -eq 0) {
                Write-Host "Null"
            } else {
                Write-Host $result.Properties["pKIExtendedKeyUsage"]
            }
            Write-Host ""

            $object = [ADSI]"LDAP://CN=$($result.Properties["cn"]),$templateContainer"
            $object.Properties["msPKI-Certificate-Application-Policy"].Value = $object.Properties["pKIExtendedKeyUsage"].Value
            $object.CommitChanges()
        }
    }
}

if ($reverseV1NullFix) {
    foreach ($result in $results) {
        if ($result.Properties["msPKI-Template-Schema-Version"] -eq 1) {
            Write-Host "Setting $($result.Properties["cn"])'s msPKI-Certificate-Application-Policy to Null"
            Write-Host ""
            
            $object = [ADSI]"LDAP://CN=$($result.Properties["cn"]),$templateContainer"
            $object.Properties["msPKI-Certificate-Application-Policy"].Value = $null
            $object.CommitChanges()       
        }
    }
}
