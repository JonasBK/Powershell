Function Get-WriteAltSecIDACEs {
<#
.SYNOPSIS
    Get ACEs in the ACL of an AD object that grants write access to AltSecurityIdentities.

    Includes Write Alt-Security-Identities and Write Public-Information.
    Not including: GenricWrite, WriteProperty all, GenericAll, Owner, WriteOwner, WriteDACL.

.PARAMETER DistinguishedName
    Distinguished name of the AD object to get ACL for.

.PARAMETER Domain
    DNS name of AD domain. Default: Current domain.

.PARAMETER ExcludeInherited
    By default the returned ACL will include inherited ACEs. Use this switch to exclude inherited ACEs.

.EXAMPLE
    PS> Get-WriteAltSecIDACEs -DistinguishedName "dc=hackme,dc=local"
    Get the ACEs for a single object based on DistinguishedName

.EXAMPLE
    PS> Get-ADObject -Filter * -SearchBase "dc=hackme,dc=local" | Get-WriteAltSecIDACEs
    Get ACEs of all AD objects under domain root by piping them into Get-WriteAltSecIDACEs

.LINK
    https://github.com/JonasBK/Powershell/blob/master/Get-WriteAltSecIDACEs.ps1

.INPUTS
    Supports both pipleine from Get-ADObject or a string formatted as DistinguishedName.
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
        [switch]$ExcludeInherited
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
        $resACEs = @()
        $acl = Get-Acl -LiteralPath "Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/$DistinguishedName"
        
        if ($ExcludeInherited) {
            $objPermissions = $acl.Access | Where-Object {
                ($_.IsInherited -eq $false)
            }
        } else {
            $objPermissions = $acl.Access
        }
  
        foreach ($permission in $objPermissions) {
                $permission | Add-Member -NotePropertyName ObjectDN -NotePropertyValue $DistinguishedName
                $permission | Add-Member -NotePropertyName InheritedObjectTypeName -NotePropertyValue $schemaIDGUID[[System.GUID]$permission.inheritedObjectType]
                $permission | Add-Member -NotePropertyName ObjectTypeName -NotePropertyValue $schemaIDGUID[[System.GUID]$permission.ObjectType]

            # Check if write Alt-Security-Identities
            if (($permission.ObjectTypeName -eq "Alt-Security-Identities" -or $Permission.ObjectTypeName -eq "Public-Information") `
                -and $permission.AccessControlType -eq "Allow" `
                -and $permission.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) {
                $resACEs += $permission
            }
        }
    
        Return $resACEs
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
