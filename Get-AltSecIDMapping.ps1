function Get-AltSecIDMapping {
  <# Example usage
    Get-AltSecIDMapping -SearchBase "CN=Users,DC=dumpster,DC=fire"
    
    <Output:>
    CN=Administrator,CN=Users,DC=dumpster,DC=fire
    X509:<S>DC=fire,DC=dumpster,CN=Users,CN=Andy3
    X509:<S>DC=fire,DC=dumpster,CN=Users,CN=Andy2
    X509:<S>DC=fire,DC=dumpster,CN=Users,CN=Andy
  #>
  param (
          [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
            )]
        [string]$SearchBase,
        [Parameter(
            Mandatory = $false
            )]
        [switch]$ExcludeStrong = $false
    )

    $searcher = [adsisearcher]""
    $searcher.SearchRoot = "LDAP://$SearchBase"
    $searcher.Filter = "(objectClass=*)"
    $searcher.PropertiesToLoad.AddRange(@("altSecurityIdentities", "distinguishedName"))

    $results = $searcher.FindAll()

    foreach ($result in $results) {
        $altSecIdentities = $result.Properties["altSecurityIdentities"]
        $selectedAltSecIdentities = $altSecIdentities | ? { 
            -not $ExcludeStrong `
            -or ($_ -notmatch '^X509:<(SKI|SHA1-PUKEY)>' `
            -and $_ -notmatch '^X509:<I>.*<SR>')
        }
        if ($selectedAltSecIdentities -ne $null) {
            Write-Host "`r"
            Write-Host $result.Properties["distinguishedName"]
            $selectedAltSecIdentities | ForEach-Object { Write-Host $_ }
        }
    }
}
