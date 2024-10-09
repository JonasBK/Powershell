<#
Script to remediate ESC15
ESC15 was found by by @Bandrel and documented here: https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc

When enrolling a certificate from ADCS, the CA populates the certificate’s Application Policies extension with the EKUs specified in the certificate template's msPKI-Certificate-Application-Policy attribute. However, if this attribute is not set in the template i.e. set to Null, the requester can specify the EKUs in the Application Policies extension themselves. The ESC15 attack exploits this behavior, making all schema version 1 templates vulnerable by default.

To mitigate this vulnerability, you can set the msPKI-Certificate-Application-Policy attribute to include the same EKUs as the pKIExtendedKeyUsage attribute for any templates where msPKI-Certificate-Application-Policy is null. This change should not cause any issues, as the only difference is that the certificate will now also include its EKUs in the Application Policies extension, preventing attackers from selecting the EKUs themselves.

Note that certain templates have both msPKI-Certificate-Application-Policy and pKIExtendedKeyUsage set to Null on purpose e.g. CA, SubCA, CrossCA. The script will not change those. Enrollment rights should be restricted to Tier 0 principals on those.
#>

# Options:
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
