# End-to-end authorization tests for the Keycloak + OpenFGA gateway.
# Run from the project root in PowerShell:   .\test\test.ps1
# If scripts are blocked:  powershell -ExecutionPolicy Bypass -File .\test\test.ps1
#
# If you changed ports:  .\test\test.ps1 -KcBase http://localhost:8090

param(
  [string]$KcBase = "http://localhost:8080",
  [string]$GwBase = "http://localhost:4000"
)

$KcToken = "$KcBase/realms/multitenant/protocol/openid-connect/token"
$script:Pass = 0
$script:Fail = 0

function Get-Token([string]$User) {
  $r = Invoke-RestMethod -Method Post -Uri $KcToken -Body @{
    grant_type = "password"; client_id = "gateway-test"
    username = $User; password = "password"
  }
  return $r.access_token
}

# Returns only the HTTP status code (works in Windows PowerShell 5.1 and PowerShell 7)
function Get-Code([string]$Method, [string]$Url, [string]$Token = "", [string]$Body = "") {
  $p = @{ Method = $Method; Uri = $Url; UseBasicParsing = $true }
  if ($Token) { $p.Headers = @{ Authorization = "Bearer $Token" } }
  if ($Body)  { $p.Body = $Body; $p.ContentType = "application/json" }
  try {
    return [int](Invoke-WebRequest @p).StatusCode
  } catch {
    if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
    throw
  }
}

function Expect([string]$Name, [int]$Want, [int]$Got) {
  if ($Want -eq $Got) { Write-Host "PASS  $Name" -ForegroundColor Green; $script:Pass++ }
  else { Write-Host "FAIL  $Name (expected $Want, got $Got)" -ForegroundColor Red; $script:Fail++ }
}

try {
  $Alice = Get-Token "alice"; $Bob = Get-Token "bob"; $Carol = Get-Token "carol"
} catch {
  Write-Host "Could not get tokens from $KcToken" -ForegroundColor Red
  Write-Host "Is Keycloak up and the 'multitenant' realm imported?  ($($_.Exception.Message))"
  exit 1
}

$Short = "doc" + (Get-Random -Maximum 99999)
$Id = "acme-$Short"
$BobId = "22222222-2222-4222-8222-222222222222"

Expect "no token is rejected"                 401 (Get-Code GET "$GwBase/me")
Expect "alice token accepted"                 200 (Get-Code GET "$GwBase/me" $Alice)
Expect "alice creates a document"             201 (Get-Code POST "$GwBase/documents" $Alice "{`"id`":`"$Short`"}")
Expect "owner can read"                       200 (Get-Code GET "$GwBase/documents/$Id" $Alice)
Expect "owner can edit"                       200 (Get-Code PUT "$GwBase/documents/$Id" $Alice)
Expect "bob blocked before sharing"           403 (Get-Code GET "$GwBase/documents/$Id" $Bob)
Expect "bob cannot share someone else's doc"  403 (Get-Code POST "$GwBase/documents/$Id/share" $Bob "{`"userId`":`"$BobId`",`"relation`":`"editor`"}")
Expect "alice shares with bob as viewer"      200 (Get-Code POST "$GwBase/documents/$Id/share" $Alice "{`"userId`":`"$BobId`",`"relation`":`"viewer`"}")
Expect "bob can read after share"             200 (Get-Code GET "$GwBase/documents/$Id" $Bob)
Expect "bob (viewer) cannot edit"             403 (Get-Code PUT "$GwBase/documents/$Id" $Bob)
Expect "carol (other tenant) blocked"         403 (Get-Code GET "$GwBase/documents/$Id" $Carol)
Expect "garbage token rejected"               401 (Get-Code GET "$GwBase/me" "abc.def.ghi")

Write-Host ""
Write-Host "Passed: $script:Pass   Failed: $script:Fail"
if ($script:Fail -gt 0) { exit 1 }