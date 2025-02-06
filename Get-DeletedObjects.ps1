# Raw LDAP enum:
$root = New-Object DirectoryServices.DirectoryEntry("LDAP://DC=BASTION,DC=LOCAL")
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.SearchRoot = $root
$searcher.Filter = "(&(isDeleted=TRUE))"
$searcher.SearchScope = "Subtree"
$searcher.Tombstone = $true  # Ensures search includes tombstoned objects
$searcher.FindAll()

# Requires List permission on the Deleted Objects container

# You can check if a SID is a deleted AD object if you run this query:
Get-ADObject -IncludeDeletedObjects -Filter 'ObjectSID -eq "S-1-5-21-2697957641-2271029196-387917394-1103"' -Properties ObjectSID

# If the SID represents a recently deleted object (and recycle bin is enabled), it will have Deleted = True in the output. If the SID does not belong to any object (incl. recently deleted), the cmdlet will output nothing. If the SID represents an existing non-deleted object, it will be shown in the output as well with the Deleted property set to nothing.

# You probably do not want to remove the permissions one by one. Here is an article incl. a PowerShell script to get rid of the unresolved SID permissions: https://www.alitajran.com/remove-orphaned-sids/
# You should run it on a DC as Domain Admin. Run the /LIST command first to see what it finds.
