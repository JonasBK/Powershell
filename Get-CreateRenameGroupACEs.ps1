Function Get-CreateRenameGroupACEs {
<#
.SYNOPSIS
    Get create group and rename ACEs in the ACL of an AD object.

.PARAMETER DistinguishedName
    Distinguished name of the AD object to get ACL for.

.PARAMETER Domain
    DNS name of AD domain. Default: Current domain.

.PARAMETER ExcludeInherited
    By default the returned ACL will include inherited ACEs. Use this switch to exclude inherited ACEs.

.PARAMETER ExcludeCreate
    Exclude create group ACEs.

.PARAMETER ExcludeRename
    Exclude rename ACEs.

.PARAMETER UniqueIdentityReferences
    Only return unique IdentityReference values and their corresponding ObjectDN values.

.PARAMETER ExcludeIdentityReferences
    List of IdentityReferences to exclude from the results.

.EXAMPLE
    PS> Get-CreateRenameGroupACEs -DistinguishedName "dc=hackme,dc=local"
    Get the ACEs for a single object based on DistinguishedName.

.EXAMPLE
    PS> Get-ADObject -Filter * -SearchBase "dc=hackme,dc=local" | Get-CreateRenameGroupACEs
    Get ACEs of all AD objects under domain root by piping them into Get-CreateRenameGroupACEs.

.LINK
    https://github.com/JonasBK/Powershell/blob/master/Get-CreateRenameGroupACEs.ps1

.INPUTS
    Supports both pipeline from Get-ADObject or a string formatted as DistinguishedName.
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
        [switch]$ExcludeCreate,
        [switch]$ExcludeRename,
        [switch]$UniqueIdentityReferences,
        [Parameter(
            Mandatory = $false
        )]
        [string[]]$ExcludeIdentityReferences
    )
 
    BEGIN {
        # Use current domain if Domain is null
        if (($null -eq $Domain) -or ($Domain -eq "")) {
            $Domain = (Get-ADDomain).DNSRoot
        }

        # Get AD schema GUIDs and their Names
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

        # Create PS drive for the selected AD domain and jump to that drive
        $oldLocation = Get-Location
        $adDriveName = "ADDrive-$($Domain.Replace('.','-'))"
        if ($oldLocation.Path -ne ($adDriveName + ":\")) {
            Get-PSDrive $adDriveName -ErrorAction SilentlyContinue | Remove-PSDrive
            $null = New-PSDrive -Name $adDriveName -PSProvider ActiveDirectory -Server $Domain -Root "//RootDSE/"
            Set-Location "$($adDriveName):"
        }

        $resACEs = @()
        $identityReferences = @{}
    }
 
    PROCESS {
        $acl = Get-Acl -LiteralPath "Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/$DistinguishedName"
        
        if ($ExcludeInherited) {
            $objPermissions = $acl.Access | Where-Object {
                ($_.IsInherited -eq $false)
            }
        } else {
            $objPermissions = $acl.Access
        }
  
        foreach ($permission in $objPermissions) {
            if ($ExcludeIdentityReferences -and $ExcludeIdentityReferences -contains $permission.IdentityReference) {
                continue
            }

            $permission | Add-Member -NotePropertyName ObjectDN -NotePropertyValue $DistinguishedName -Force
            $permission | Add-Member -NotePropertyName InheritedObjectTypeName -NotePropertyValue $schemaIDGUID[[System.GUID]$permission.inheritedObjectType] -Force
            $permission | Add-Member -NotePropertyName ObjectTypeName -NotePropertyValue $schemaIDGUID[[System.GUID]$permission.ObjectType] -Force

            if (-not $ExcludeRename) {
                # Check if rename permission
                if (($permission.ObjectTypeName -eq "RDN" `
                        -or $permission.ObjectTypeName -eq "Public-Information" `
                        -or $permission.ObjectType -eq "00000000-0000-0000-0000-000000000000") `
                    -and $permission.AccessControlType -eq "Allow" `
                    -and ($permission.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) `
                    -and ($permission.InheritanceType -eq [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None `
                        -or $permission.InheritanceType -eq [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren)) {
                    $resACEs += $permission
                }
            }

            if (-not $ExcludeCreate) {
                # Check if create permission
                if (($permission.ObjectTypeName -eq "Group" -or $permission.ObjectType -eq "00000000-0000-0000-0000-000000000000") `
                    -and $permission.AccessControlType -eq "Allow" `
                    -and ($permission.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::CreateChild) `
                    -and ($permission.InheritanceType -eq [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None `
                        -or $permission.InheritanceType -eq [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All `
                        -or $permission.InheritanceType -eq [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren)) {
                    $resACEs += $permission
                }
            }
        }

        if ($UniqueIdentityReferences) {
            foreach ($ace in $resACEs) {
                if (-not $identityReferences.ContainsKey($ace.IdentityReference)) {
                    $identityReferences[$ace.IdentityReference] = @()
                }
                if ($ace.ObjectDN -notin $identityReferences[$ace.IdentityReference]) {
                    $identityReferences[$ace.IdentityReference] += $ace.ObjectDN
                }
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

        if ($UniqueIdentityReferences) {
            $identityReferences.GetEnumerator() | ForEach-Object {
                [PSCustomObject]@{
                    IdentityReference = $_.Key
                    ObjectDNs         = $_.Value -join ", "
                }
            }
        } else {
            $resACEs
        }
    }
}
