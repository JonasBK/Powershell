$templateName = "TemplateName"   # Use CN, not display name
$principalName = "principal"     # SAM account name of principal
# Find the certificate template
$rootDSE = New-Object DirectoryServices.DirectoryEntry("LDAP://RootDSE")
$template = [ADSI]"LDAP://CN=$templateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$($rootDSE.configurationNamingContext)"
# Construct the ACE
$account = New-Object System.Security.Principal.NTAccount($principalName)
$sid = $account.Translate([System.Security.Principal.SecurityIdentifier])
$ace = New-Object DirectoryServices.ActiveDirectoryAccessRule(
    $sid,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
    [System.Security.AccessControl.AccessControlType]::Allow
)
# Add the new ACE to the ACL
$acl = $template.psbase.ObjectSecurity
$acl.AddAccessRule($ace)
$template.psbase.CommitChanges()
