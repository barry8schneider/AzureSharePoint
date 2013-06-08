Get-AzureVM | ? {$_.ServiceName -eq "PlanA"} | Remove-AzureVM
sleep 60
Get-AzureService "PlanA" | Remove-AzureService -Force
sleep 60
Get-AzureDisk | where {$_.DiskName -like "PlanA*"} | Remove-AzureDisk

$cert = ls Cert:\LocalMachine\Root | where {$_.Subject -match "PlanA"}

function RemoveCertFromRootStore
{
    param($cert)

    $storeName = [System.Security.Cryptography.X509Certificates.StoreName]::Root
    $storeLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
    $store = new-object system.security.cryptography.x509certificates.x509Store -ArgumentList $storeName, $storeLocation
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $store.Remove($cert)
    $store.Close()
}

RemoveCertFromRootStore $cert

<#
Get-AzureDisk | Where {$_.DiskName -match "PlanASQL"} | Remove-AzureDisk -DeleteVHD
Get-AzureRemoteDesktopFile -ServiceName "DG-Controller" -Name "DG-Controller" -Launch
Get-AzureVM EightSQL | Remove-AzureVM
Get-AzureService EightSQL | Remove-AzureService -Force
Get-AzureDisk | where {$_.SourceImageName -ne $null -and $_.DiskName -like "EightSQL*"} | Remove-AzureDisk

$cert = ls Cert:\LocalMachine\Root | where {$_.Subject -match "EightSQL"}

function RemoveCertFromRootStore
{
    param($cert)

    $storeName = [System.Security.Cryptography.X509Certificates.StoreName]::Root
    $storeLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
    $store = new-object system.security.cryptography.x509certificates.x509Store -ArgumentList $storeName, $storeLocation
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $store.Remove($cert)
    $store.Close()
}

RemoveCertFromRootStore $cert

#>