param(
  [string]$InputKy = "projects\mini-kyc.ky",
  [int]$TimeoutMs = 15000
)

$ErrorActionPreference = "Stop"
$IDE = "E:\yoyo\yoyo-ide"
Set-Location $IDE

# Step 1: Clean up any previous outputs
Remove-Item -Force "input.ky", "output.exe", "stdout.log", "stderr.log", "mini-kyc-patched.exe" -ErrorAction SilentlyContinue

# Step 2: Copy input .ky to CWD as input.ky
if (Test-Path $InputKy) {
  Copy-Item $InputKy "input.ky" -Force
  Write-Host "[*] Copied $InputKy -> input.ky ($((Get-Item 'input.ky').Length) bytes)"
} else {
  Write-Host "[!] Input file not found: $InputKy"
  exit 1
}

# Step 3: Run mini-kyc.exe with timeout via Start-Process
Write-Host "[*] Running: mini-kyc.exe"
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$proc = Start-Process -FilePath ".\mini-kyc.exe" -NoNewWindow -PassThru `
  -RedirectStandardOutput "stdout.log" -RedirectStandardError "stderr.log"
Write-Host "[*] PID: $($proc.Id)"
$exited = $proc.WaitForExit($TimeoutMs)
$sw.Stop()

if (-not $exited) {
  Write-Host "[!] TIMEOUT after ${TimeoutMs}ms ($($sw.Elapsed.TotalSeconds)s) - killing..."
  $proc.Kill()
  Write-Host "[!] Killed."
  $exitCode = -1
} else {
  $exitCode = $proc.ExitCode
  Write-Host "[*] Exited in $($sw.Elapsed.TotalSeconds)s with code $exitCode"
}

# Step 4: Show output
Write-Host "`n=== stdout ==="
if ((Get-Item "stdout.log" -ErrorAction SilentlyContinue).Length -gt 0) {
  Get-Content "stdout.log"
} else { Write-Host "(empty)" }

Write-Host "`n=== stderr ==="
if ((Get-Item "stderr.log" -ErrorAction SilentlyContinue).Length -gt 0) {
  Get-Content "stderr.log"
} else { Write-Host "(empty)" }

# Step 5: Check output.exe
if (Test-Path "output.exe") {
  $sz = (Get-Item "output.exe").Length
  Write-Host "`n[✓] output.exe produced: $sz bytes"
} else {
  Write-Host "`n[✗] output.exe NOT produced"
}

# Step 6: Cleanup input.ky so it doesn't interfere with future runs
Remove-Item "input.ky" -Force -ErrorAction SilentlyContinue

Write-Host "`n[*] Done."
