# Will output all the ACLs of a domain in four files

Set-ExecutionPolicy Bypass -Force
. .\Get-ADObjectACL.ps1 # https://github.com/JonasBK/Powershell/blob/master/Get-ADObjectACL.ps1

# Domain partition
Get-ADObject -Filter * | Select -ExpandProperty DistinguishedName | Get-ADObjectACL -ExcludeInherited -IncludeOwner -FullOutput > acls-domain.txt

# Schema partition
Get-ADObject -Filter * -SearchBase "CN=Schema,CN=Configuration,DC=external,DC=local" | Select -ExpandProperty DistinguishedName | Get-ADObjectACL -ExcludeInherited -IncludeOwner -FullOutput > acls-schema.txt

# Config partition
Get-ADObject -Filter * -SearchBase "CN=Configuration,DC=external,DC=local" | Select -ExpandProperty DistinguishedName | Get-ADObjectACL -ExcludeInherited -IncludeOwner -FullOutput > acls-config.txt

# Default sec descriptors
$objs = Get-ADObject -Filter * -SearchBase "CN=Schema,CN=Configuration,DC=external,DC=local" -Properties defaultSecurityDescriptor 
foreach ($obj in $objs) {
    if ($obj.ObjectClass -eq "classSchema") {
        $obj.defaultSecurityDescriptor >> acls-classes.txt
        $obj.DistinguishedName >> acls-classes.txt
        ConvertFrom-SddlString -Sddl $obj.defaultSecurityDescriptor | Select -ExpandProperty DiscretionaryAcl >> acls-classes.txt
        "" >> acls-classes.txt
        "" >> acls-classes.txt
    }
}
