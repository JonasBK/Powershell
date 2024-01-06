$root = [ADSI]"LDAP://DC=EXTERNAL,DC=LOCAL"
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.SearchRoot = $root
$searcher.filter = "(objectclass=domain)"
$searcher.FindAll()
