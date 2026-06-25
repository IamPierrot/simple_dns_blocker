$adapters = Get-NetAdapter |
    Where-Object { 
        $_.Status -eq "Up" -and ($_.Name -like "Wi-Fi*" -or $_.Name -like "Ethernet*" -or $_.Name -like "vEthernet*")
    }

if ($adapters.Count -eq 0) {
    Write-Host "No active network adapter found." -ForegroundColor Red
    exit 1
}

foreach ($adapter in $adapters) {
    Write-Host "Restoring DNS on $($adapter.Name)..." -ForegroundColor Yellow

    Set-DnsClientServerAddress  -InterfaceAlias $adapter.Name -ResetServerAddresses
}

ipconfig /flushdns | Out-Null

Write-Host ""
Write-Host "DNS restored to automatic (DHCP)." -ForegroundColor Green
