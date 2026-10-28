$files = Get-ChildItem -Path venv -Include *.exe,*.dll,*.pyd -Recurse | Select-Object -ExpandProperty FullName
$sigs = Get-AuthenticodeSignature -FilePath $files
$results = @()
foreach ($s in $sigs) {
    $results += [PSCustomObject]@{
        Path = $s.Path
        Status = $s.Status.ToString()
        Signer = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { $null }
    }
}
$results | ConvertTo-Json -Depth 2 | Out-File -Encoding utf8 scratch\authenticode_results.json
Write-Host "Done checking $($results.Count) files"
