function Expand-LatestZip {
    [CmdletBinding()]
    param()

    $zipFiles = Get-ChildItem -Filter *.zip | Sort-Object LastWriteTime -Descending

    if ($zipFiles.Count -eq 0) {
        Write-Host "No zip files found in the current folder."
        return
    }

    $latestZip = $zipFiles[0].FullName
    $outputFolder = Join-Path -Path $PWD -ChildPath $($zipFiles[0].BaseName)

    Write-Host "Unzipping $latestZip to $outputFolder..."

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($latestZip, $outputFolder)

    Write-Host "Extraction complete. Files are extracted to $outputFolder."
}
