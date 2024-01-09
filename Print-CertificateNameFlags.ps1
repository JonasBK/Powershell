$msPKICertificateNameFlag = "1107296256"

$flagTable = @{
    0x00000001 = "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT"
    0x00010000 = "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME"
    0x00400000 = "CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS"
    0x00800000 = "CT_FLAG_SUBJECT_ALT_REQUIRE_SPN"
    0x01000000 = "CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID"
    0x02000000 = "CT_FLAG_SUBJECT_ALT_REQUIRE_UPN"
    0x04000000 = "CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL"
    0x08000000 = "CT_FLAG_SUBJECT_ALT_REQUIRE_DNS"
    0x10000000 = "CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN"
    0x20000000 = "CT_FLAG_SUBJECT_REQUIRE_EMAIL"
    0x40000000 = "CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME"
    0x80000000 = "CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH"
    0x00000008 = "CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME"
}

$flags = @()
$maxHexLength = ($flagTable.Keys | ForEach-Object { $_.ToString("X").Length }) | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum

foreach ($flag in $flagTable.Keys) {
    if ($msPKICertificateNameFlag -band $flag) {
        $formattedFlag = "0x$("{0:X$maxHexLength}" -f $flag) $($flagTable[$flag])"
        $flags += $formattedFlag
    }
}

Write-Host "The following flags are present in the decimal value $($msPKICertificateNameFlag):"
foreach ($flag in $flags) {
    Write-Host "- $flag"
}
