<#
 .SYNOPSIS
  Start hyperdbg-mcp over Streamable HTTP with its bearer token read from a file.

 .DESCRIPTION
  The token is handed to the server through $env:HYPERDBG_MCP_TOKEN, never on a
  command line (other processes can read those). Keep the token file readable by
  Administrators only. Arguments after the named ones go to hyperdbg-mcp as-is.

  The server is restarted after -RestartDelay seconds whenever it exits with a
  non-zero code: Task Scheduler's "restart on failure" only covers a task that
  fails to start, not one whose process dies later. Pass -RestartDelay 0 to run
  it once.

 .EXAMPLE
  # As Administrator, from an elevated shell or a scheduled task:
  .\start-http.ps1 -TokenFile C:\ProgramData\hyperdbg-mcp\token `
      --lib-path C:\HyperDbg\libhyperdbg.dll --audit-log C:\ProgramData\hyperdbg-mcp\audit.jsonl
#>
param(
    [string]$TokenFile = (Join-Path $env:ProgramData 'hyperdbg-mcp\token'),
    [string]$Server = 'hyperdbg-mcp',
    [int]$RestartDelay = 5,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ServerArgs
)
$ErrorActionPreference = 'Stop'
$env:HYPERDBG_MCP_TOKEN = (Get-Content -Raw -LiteralPath $TokenFile).Trim()
while ($true) {
    & $Server --transport http @ServerArgs
    $code = $LASTEXITCODE
    if ($code -eq 0 -or $RestartDelay -le 0) {
        exit $code
    }
    Write-Warning "hyperdbg-mcp exited with code $code; restarting in $RestartDelay s"
    Start-Sleep -Seconds $RestartDelay
}
