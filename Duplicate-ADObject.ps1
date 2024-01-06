$OriginalObjectDN = "CN=Administrator,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=dumpster,DC=fire"
$NewName = "AdministratorCopy"
$NewPath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=dumpster,DC=fire"

# Retrieve the properties of the original object
$originalObject = Get-AdObject $OriginalObjectDN

# Create a new object with the retrieved properties
New-AdObject -Instance $originalObject -Name $NewName -Type $originalObject.ObjectClass -Path $NewPath

$duplicatedObject = Get-ADObject -Identity "CN=$NewDisplayName,$NewPath"
$objectToDuplicate = Get-AdObject $OriginalObjectDN -Properties *

# Duplicate all attributes of the original object to the new one
foreach ($attribute in $objectToDuplicate.psobject.Properties) {
    if ($attribute.Name -ne "ObjectGUID" -and $attribute.Name -ne "ObjectSid" -and $attribute.Name -ne "DisplayName") {
        Set-ADObject -Identity $duplicatedObject -Add @{ $attribute.Name = $attribute.Value }
    }
}
