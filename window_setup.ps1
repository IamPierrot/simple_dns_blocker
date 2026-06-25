Write-Host "Building DNS server..." -ForegroundColor Cyan

go build -o dns-server.exe cmd/server/main.go

if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Build success." -ForegroundColor Green

$adapters = Get-NetAdapter |
    Where-Object {
        $_.Status -eq "Up" -and
        $_.Name -match "Wi-Fi|Ethernet"
    }

if ($adapters.Count -eq 0) {
    Write-Host "No active network adapter found." -ForegroundColor Red
    exit 1
}


$adapters | Format-Table Name, InterfaceDescription

$adapterName = Read-Host "Adapter"

Set-DnsClientServerAddress `
    -InterfaceAlias $adapterName `
    -ServerAddresses @("127.0.0.1", "::1")

ipconfig /flushdns | Out-Null

Write-Host ""
Write-Host "DNS configured successfully." -ForegroundColor Green
Write-Host "IPv4 DNS: 127.0.0.1"
Write-Host "IPv6 DNS: ::1"
