$ObjectDN = "CN=victim,CN=Users,DC=dumpster,DC=fire"
$AttrName = "mail"
$AttrValue = "dummy@mail.com"

$object = [ADSI]"LDAP://$ObjectDN"
$object.psbase.Properties["$AttrName"].Value = $AttrValue
$object.psbase.CommitChanges()
