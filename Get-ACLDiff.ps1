$aceList1FilePath = ".\Exchange AD ACL test\Exchange RBAC model\acls-domain.txt"
$aceList2FilePath = ".\Exchange AD ACL test\Exchange AD split model\acls-domain.txt"

# Function to parse ACEs from text format into objects
function Parse-ACE {
    param ($aceText)
    
    $aceObjects = @()
    $currentAce = New-Object -TypeName PSObject
    $aceText -split "`r`n" | ForEach-Object {
        if ([string]::IsNullOrWhiteSpace($_)) {
            # Empty line indicates the end of an ACE, add it to the list and reset the current ACE object
            $aceObjects += $currentAce
            $currentAce = New-Object -TypeName PSObject
        }
        else {
            # Check if the line starts with whitespace, if so, it's a continuation of the previous property's value
            if ($_ -match '^\s') {
                $lastProperty = $currentAce.PSObject.Properties.Name | Select-Object -Last 1
                $currentAce.$lastProperty += $_.Trim()
            }
            else {
                $key, $value = $_ -split ":", 2
                $currentAce | Add-Member -MemberType NoteProperty -Name $key.Trim() -Value $value.Trim()
            }
        }
    }
    # Add the last ACE object to the list
    $aceObjects += $currentAce
    return $aceObjects
}

# Function to import ACE list from a text file
function Import-ACEList {
    param ($filePath)
    
    $fileContent = Get-Content -Path $filePath -Encoding Unicode
    return Parse-ACE -aceText $fileContent
}

# Import ACE lists from text files
$aceList1 = Import-ACEList -filePath $aceList1FilePath
$aceList2 = Import-ACEList -filePath $aceList2FilePath

# Compare the two lists of ACEs
$addedAces = Compare-Object -ReferenceObject $aceList1 -DifferenceObject $aceList2 -Property ObjectDN, InheritedObject, Object, ActiveDirectoryRights, InheritanceType, ObjectType, InheritedObjectType, ObjectFlags, AccessControlType, IdentityReference, IsInherited, InheritanceFlags, PropagationFlags -PassThru |
    Where-Object { $_.SideIndicator -eq 'ACE Added' }

$removedAces = Compare-Object -ReferenceObject $aceList1 -DifferenceObject $aceList2 -Property ObjectDN, InheritedObject, Object, ActiveDirectoryRights, InheritanceType, ObjectType, InheritedObjectType, ObjectFlags, AccessControlType, IdentityReference, IsInherited, InheritanceFlags, PropagationFlags -PassThru |
    Where-Object { $_.SideIndicator -eq 'ACE Removed' }

# Output the added and removed ACEs
Write-Host "Added ACEs:"
$addedAces | ForEach-Object {
    $_
}

Write-Host "`nRemoved ACEs:"
$removedAces | ForEach-Object {
    $_
}
