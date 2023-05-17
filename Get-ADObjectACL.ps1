# From Improsec blog post: https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research

Function Get-ADObjectACL {
<#
.SYNOPSIS
    Get all ACEs in the ACL of an AD object. This cmdlet is mainly a replacement for Get-ACL because it translates AD schema GUIDs into friendly names.

.PARAMETER DistinguishedName
    Distinguished name of the AD object to get ACL for.

.PARAMETER Domain
    DNS name of AD domain. Default: Current domain.

.PARAMETER ExcludeInherited
    By default the returned ACL will include inherited ACEs. Use this switch to exclude inherited ACEs.

.PARAMETER IncludeOwner
    By default the returned ACL will not include the owner of the object. Use this switch to include the owner as an ACE in the output.

.PARAMETER FullOutput
    By default the ACL will include a limited and user-friendly property names. Use this to switch to return all properties with original names.

.EXAMPLE
    PS> Get-ADObjectACL -DistinguishedName "dc=hackme,dc=local"
    Get ACL for a single object based on DistinguishedName

.EXAMPLE
    PS> "dc=hackme,dc=local" | Get-ADObjectACL
    Get ACL for a single object based on DistinguishedName

.EXAMPLE
    PS> Get-ADObject -Filter * -SearchBase "dc=hackme,dc=local" | Get-ADObjectACL
    Get ACLs of all ADObjects under domain root by piping them into Get-ADObjectACL

.LINK
    https://improsec.com/

.LINK
    https://github.com/improsec

.INPUTS
    Supports both pipleine from Get-ADObject or a string formatted as DistinguishedName.

.OUTPUTS
System.Array of PSCustomObject, each object being an ACE. Example of one ACE object from AD Object with DistinguishedName "dc=hackme,dc=local":

Type            : Allow
Object          : dc=hackme,dc=local
Principal       : BUILTIN\Pre-Windows 2000 Compatible Access
Permission      : ReadProperty
Property        : User-Account-Restrictions
IsInherited     : False
Inheritance     : Descendents
InheritedObject : User

#>
 
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
            )]
        [string]$DistinguishedName,
        [Parameter(
            Mandatory = $false
            )]
        [string]$Domain,
        [Parameter(
            Mandatory = $false
            )]
        [switch]$ExcludeInherited,
        [Parameter(
            Mandatory = $false
            )]
        [switch]$IncludeOwner,
        [Parameter(
            Mandatory = $false
            )]
        [switch]$FullOutput
    )
 
    BEGIN {
        # Use current domain if Domian is null
        if (($null -eq $Domain) -or ($Domain -eq "")) {
            $Domain = (Get-ADDomain).DNSRoot
        }

        # Get AD schma GUIDs and their Names
        ### Currently all GUIDs are gathered into a hashtable which is later queried per object. Could be changed so that a lookup is performer per object.
        $ADRootDSE = Get-ADRootDSE -Server $Domain
        $schemaNamingContext = $ADRootDSE.schemaNamingContext
        $configurationNamingContext = $ADRootDSE.configurationNamingContext

        # Initialize hashtable
        $schemaIDGUID = @{'00000000-0000-0000-0000-000000000000' = 'All'}
        Get-ADObject -SearchBase $schemaNamingContext -LDAPFilter '(schemaIDGUID=*)' -Server $Domain -Properties name, schemaIDGUID | ForEach-Object { $schemaIDGUID.add([System.GUID]$_.schemaIDGUID, $_.name) }
        Get-ADObject -SearchBase "CN=Extended-Rights,$configurationNamingContext" -LDAPFilter '(objectClass=controlAccessRight)' -Server $Domain -Properties name, rightsGUID | ForEach-Object {
            if (!$schemaIDGUID.ContainsKey([System.GUID]$_.rightsGUID)) {
                $schemaIDGUID.add([System.GUID]$_.rightsGUID, $_.name)
            }
        }

        # Create PS drive for the select AD domain and jump to that drive
        $oldLocation = Get-Location
        $adDriveName = "ADDrive-$($Domain.Replace('.','-'))"
        if ($oldLocation.Path -ne ($adDriveName + ":\")) {
            Get-PSDrive $adDriveName -ErrorAction SilentlyContinue | Remove-PSDrive
            $null = New-PSDrive -Name $adDriveName -PSProvider ActiveDirectory -Server $Domain -Root "//RootDSE/"
            Set-Location "$($adDriveName):"
        }
    }
 
    PROCESS {
        $acl = Get-Acl -LiteralPath "Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/$DistinguishedName"
        
        if ($ExcludeInherited) {
            $ObjPermissions = $acl.Access | Where-Object {
                ($_.IsInherited -eq $false)
            }
        } else {
            $ObjPermissions = $acl.Access
        }
        
        # Add Owner as ACE
        if ($IncludeOwner) {
            $ObjPermissions += (New-Object PSObject -Property @{
                ActiveDirectoryRights = "Owner"
                InheritanceType       = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
                ObjectType            = [System.GUID]"00000000-0000-0000-0000-000000000000"
                InheritedObjectType   = [System.GUID]"00000000-0000-0000-0000-000000000000"
                ObjectFlags           = [System.Security.AccessControl.ObjectAceFlags]::None
                AccessControlType     = [System.Security.AccessControl.AccessControlType]::Allow
                IdentityReference     = [System.Security.Principal.NTAccount]::new($acl.Owner)
                IsInherited           = $false
                InheritanceFlags      = [System.Security.AccessControl.InheritanceFlags]::None
                PropagationFlags      = [System.Security.AccessControl.PropagationFlags]::None
            })
        }
        
        $ObjPermissions | Add-Member -NotePropertyName ObjectDN -NotePropertyValue $DistinguishedName

        foreach ($Permission in $ObjPermissions) {
            $Permission | Add-Member -NotePropertyName InheritedObject -NotePropertyValue $schemaIDGUID[[System.GUID]$Permission.inheritedObjectType]
            $Permission | Add-Member -NotePropertyName Object -NotePropertyValue $schemaIDGUID[[System.GUID]$Permission.ObjectType]
        }
    
        if ($ObjPermissions -ne $null) {
            if ($FullOutput) {
                Return $ObjPermissions
            } else {
                Return $ObjPermissions | select @{N="Type"; E={$_.AccessControlType}},
                    @{N="Object";E={$_.ObjectDN}},
                    @{N="Principal";E={$_.IdentityReference}},
                    @{N="Permission"; E={$_.ActiveDirectoryRights}},
                    @{N="Property";E={$_.Object}},
                    @{N="IsInherited"; E={$_.IsInherited}},
                    @{N="Inheritance"; E={$_.InheritanceType}},
                    @{N="InheritedObject"; E={$_.InheritedObject}}
                }
        }
    }

    END {
        # Remove the PS drive again
        if ($oldLocation.Path -ne ($adDriveName + ":\")) {
            try {
                Set-Location $oldLocation -ErrorAction Stop
                Get-PSDrive $adDriveName -ErrorAction SilentlyContinue | Remove-PSDrive
            }
            catch [System.Management.Automation.DriveNotFoundException] {
                # Stay at current location if our old has been removed
            }
        }
    }
}
