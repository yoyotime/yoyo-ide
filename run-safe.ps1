param(
  [string]$Exe = ".\mini-kyc.exe",
  [string]$InputFile = "",
  [int]$TimeoutMs = 5000
)

$proc = Start-Process -FilePath $Exe -ArgumentList $InputFile -NoNewWindow -PassThru -RedirectStandardOutput "stdout.log" -RedirectStandardError "stderr.log"
Write-Host "[*] PID $($proc.Id): $Exe $InputFile"

$null = $proc.WaitForExit($TimeoutMs)
if (-not $proc.HasExited) {
  Write-Host "[!] TIMEOUT after ${TimeoutMs}ms - killing PID $($proc.Id)"
  $proc.Kill()
  Write-Host "[!] Killed."
} else {
  Write-Host "[*] Exit code: $($proc.ExitCode)"
}
Write-Host "[*] stdout:"
Get-Content "stdout.log" -ErrorAction SilentlyContinue
Write-Host "[*] stderr:"
Get-Content "stderr.log" -ErrorAction SilentlyContinue
