$searcher = [adsisearcher]""
$searcher.SearchRoot = "LDAP://DC=dumpster,DC=fire"
$searcher.Filter = "(objectClass=*)"
$searcher.PropertiesToLoad.AddRange(@("distinguishedName", "minPwdAge"))

$results = $searcher.FindAll()

foreach ($result in $results) {
    if ($result.Properties["minPwdAge"] -ne "") {
        $result.Properties["distinguishedName"]
        $result.Properties["minPwdAge"]
    }
}
