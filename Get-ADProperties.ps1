$searcher = [adsisearcher]""
$searcher.SearchRoot = "LDAP://DC=dumpster,DC=fire"
$searcher.Filter = "(objectClass=*)"
$searcher.PropertiesToLoad.AddRange(@("lockoutDuration", "distinguishedName"))

$results = $searcher.FindAll()

foreach ($result in $results) {
    Write-Host "$($result.Properties["distinguishedName"]) $($result.Properties["lockoutDuration"])"
}
