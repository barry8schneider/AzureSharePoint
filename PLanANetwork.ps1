<#
    Steps:
    1. Install and Configure Azure PowerShell.
    2. Create PlanADC in Azure
    3. Install and Configure Active Directory
    4. Create PlanASQL in Azure
    5. Configure SQL
    6. Create SharePoint Server
    7. Configure Sharepoint

    Configure Client:
        enable-wsmancredssp -role client -delegatecomputer "*.cloudapp.net"

        Computer Configuration -> Administrative Templates -> System -> Credentials Delegation ->
        Allow Delegating Fresh Credentials with NTLM-only server authentication
#>

#region Helper Functions

function WaitForReadyRole
{
    param($serverName = (Read-Host "What is the name of the server?"))

    $y = $true

    while ($y) 
    {
        sleep 1

        $vm = Get-AzureVM $serverName
        
        if ($vm.InstanceStatus -eq "Provisioning")
        {
            Write-Host $serverName "still provisioning" -ForegroundColor Yellow
        }
        elseif ($vm.InstanceStatus -eq "ReadyRole")
        {
            $y = $false
            Write-Host $serverName "completed" -ForegroundColor Yellow
        }
    }
}

if (!(Test-Path function:Invoke-Admin))
{
    function Invoke-Admin {
        param ( [string]$program = $(throw "Please specify a program" ),
                [string]$argumentString = "",
                [switch]$waitForExit )


        $psi = new-object "Diagnostics.ProcessStartInfo" -ArgumentList $program
        $psi.Arguments = $argumentString
        $psi.Verb = "runas"
        $proc = [Diagnostics.Process]::Start($psi)
        if ( $waitForExit ) {
            $proc.WaitForExit();
        }

        # EXAMPLE: sudo -program powershell -argumentString "-noexit", "-command ps"
    }
}

if (!(Test-Path alias:sudo))
{
    new-alias sudo invoke-admin
}

function MakeCert
{
    f:\makecert -sky exchange -eku "1.3.6.1.5.5.7.3.2" -r -n "CN=PlanASQL.Cloud8ight.com" -pe -a sha1 -len 2048 -ss My "PlanASQL.cer"
}

function AddCert
{
    certutil -addstore My "C:\PlanASQL.cer"
}

function ChangeWinRMCert
{
    $thumbprint = (ls Cert:\LocalMachine\My | ? {$_.Subject -match "Cloud8ight"}).thumbprint
    remove-wsmaninstance -resourceuri winrm/config/listener -selectorset @{address="*";transport="https"}
    new-wsmaninstance -resourceuri winrm/config/listener -selectorset @{address="*";transport="https"} -ValueSet @{HostName="PlanASQL.Cloud8ight.com";CertificateThumbprint=$thumbprint}
}

#endregion

#region Step 1 Azure Powershell

function InstallAzurePowerShell
{
    cmd /C 'C:\Program Files\microsoft\web platform installer\WebPICMD.exe' /install /products:WindowsAzurePowershell /AcceptEula
}

function InstallCert
{
    param([string]$password = (Read-Host "What is your password:"))
    $pass = ConvertTo-SecureString $password -AsPlainText -Force
    Import-PfxCertificate -FilePath "C:\Users\ian.philpot\Downloads\certs\AdminianAzure.pfx" -CertStoreLocation "Cert:\CurrentUser\My" `
        -Password $pass -Exportable
}

function SetupAzure 
{
    #Set-ExecutionPolicy Unrestricted -Force

    Import-Module "C:\Program Files (x86)\Microsoft SDKs\Windows Azure\PowerShell\Azure\Azure.psd1"

    $certThumbprint = "[cert thumbprint]"

    $mySubID = "[sub id]"
    $myCert = Get-Item cert:\CurrentUser\My\$certThumbprint
    $mySubName = "PFE Azure"
    $myStorageSubscription = "planastorage"
    Write-Host "Setting up Subscription" -ForegroundColor Yellow
    Set-AzureSubscription -SubscriptionName $mySubName -Certificate $myCert -SubscriptionID $mySubID -CurrentStorageAccount $myStorageSubscription
    Write-Host "Selecting Subscription" -ForegroundColor Yellow
    Select-AzureSubscription -SubscriptionName $mySubName
}

#endregion

#region Step 2 PlanADC

function CreatePlanADC
{
    param($password = (Read-Host "What password would you like configure for the ADMINISTRATOR account?"))

    #Configure Azure Specifics
    $imageWin2k12 = "a699494373c04fc0bc8f2bb1389d6106__Windows-Server-2012-Datacenter-201305.01-en.us-127GB.vhd"

    #Configure machine specifics
    $instanceSize = @{"ExtraSmall" = "ExtraSmall"; "Small" = "Small"; "Medium" = "Medium"; "Large" = "Large"; "ExtraLarge" = "ExtraLarge"}
    $dcDNS = New-AzureDns -name "PlanADCDNS" -IPAddress "127.0.0.1"
    $memberDNS = New-AzureDns -Name "PlanAMemberDNS" -IPAddress "10.10.2.4"
    $machineName = "PlanADC"
    $serviceName = "PlanA"

    #Setup Azure networking
    $location = @{"WestUS" = "West US"; "EastUS" = "East US"; "EastAsia" = "East Asia"; "SoutheastAsia" = "Southeast Asia"; "NorthEurope" = "North Europe"; `
        "WestEurope" = "West Europe"}

    $affinityGroup = "PlanA"
    $virtualNetwork = "PlanANetwork"
    $subnet = "PlanASu"

    # DC: Azure VM using defualt image
    $config = New-AzureVMConfig -Name $machineName -Label $machineName -ImageName $imageWin2k12 -InstanceSize $instanceSize.Small | 
        Add-AzureProvisioningConfig -Windows -Password $password -AdminUsername "Adminian" | Set-AzureSubnet $subnet

    New-AzureVM -ServiceName $serviceName -VMs $config -VNetName $virtualNetwork -DnsSettings $memberDNS, $dcDNS -AffinityGroup $affinityGroup -WaitForBoot -Verbose

    Get-AzureVM $machineName | Set-AzureOSDisk -HostCaching ReadOnly

    # Add Installs Disk
    Get-AzureVM $machineName | Add-AzureDataDisk -Import -DiskName "Installs" -LUN 0 | Update-AzureVM
}

function InstallPlanADCRemotePSCert
{
    $serviceName = "PlanA"
    $vmName = "PlanADC"

	$WinRMCert = (Get-AzureVM -ServiceName $serviceName -Name $vmName | select -ExpandProperty vm).DefaultWinRMCertificateThumbprint
	$AzureX509cert = Get-AzureCertificate -ServiceName $serviceName -Thumbprint $WinRMCert -ThumbprintAlgorithm sha1

	$certTempFile = [IO.Path]::GetTempFileName()
    $AzureX509cert.Data | Out-File $certTempFile

	# Target The Cert That Needs To Be Imported
	$CertToImport = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $certTempFile

	$store = New-Object System.Security.Cryptography.X509Certificates.X509Store "Root", "LocalMachine"
	$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
	$store.Add($CertToImport)
	$store.Close()
	
	Remove-Item $certTempFile
}

#endregion

#region Step 3 Active Directory

function DCPromoPlanADC
{
    # TASK: enable-wsmancredssp -role client -delegatecomputer "*.cloudapp.net"
    # TASK: Computer Configuration -> Administrative Templates -> System -> Credentials Delegation -> 
        # Allow Delegating Fresh Credentials with NTLM-only server authentication 

    param($password = (Read-Host "What is the password for the ADMINISTRATOR account?"))

    # Set Username
    $user = "Adminian"

    # Set Password
    $pass = ConvertTo-SecureString $password -AsPlainText -Force

    # Create Credential
    $cred = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $pass

    $uri = Get-AzureWinRMUri -ServiceName "PlanA" -Name "PlanADC"

    Invoke-Command -ComputerName $uri.Host -Port $uri.Port -Credential $cred -UseSSL -ScriptBlock {
        Import-Module ServerManager

        Install-WindowsFeature AD-Domain-Services, RSAT-ADDS

        $safePass = ConvertTo-SecureString "Pass@word" -AsPlainText -Force

        Import-Module ADDSDeployment

        Install-ADDSForest `
            -CreateDnsDelegation:$false `
            -DatabasePath "C:\Windows\NTDS" `
            -DomainMode "Win2012" `
            -DomainName "plana.io" `
            -DomainNetbiosName "PLANA" `
            -ForestMode "Win2012" `
            -InstallDns:$true `
            -LogPath "C:\Windows\NTDS" `
            -NoRebootOnCompletion:$false `
            -SysvolPath "C:\Windows\SYSVOL" `
            -SafeModeAdministratorPassword $safePass `
            -Force:$true

    }

    Restart-AzureVM -Name "PlanADC" -ServiceName "PlanA" -Verbose
}

function ConfigureAD
{
    param($password = (Read-Host "What is the password for the ADMINISTRATOR account?"))

    # Set Username
    $user = "plana\Adminian"

    # Set Password
    $pass = ConvertTo-SecureString $password -AsPlainText -Force

    # Create Credential
    $cred = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $pass

    $uri = Get-AzureWinRMUri -ServiceName "PlanA" -Name "PlanADC"

    Invoke-Command -ComputerName $uri.Host -Port $uri.Port -Credential $cred -UseSSL -ScriptBlock {
        Import-Module ActiveDirectory

        New-ADOrganizationalUnit -Name "PlanA" -DisplayName "PlanA" -Path "DC=PlanA,DC=io"
        New-ADOrganizationalUnit -Name "Users" -DisplayName "Users" -Path "OU=PlanA,DC=PlanA,DC=io"
        New-ADOrganizationalUnit -Name "Groups" -DisplayName "Groups" -Path "OU=PlanA,DC=PlanA,DC=io"
        New-ADOrganizationalUnit -Name "Computers" -DisplayName "Computers" -Path "OU=PlanA,DC=PlanA,DC=io"
        New-ADOrganizationalUnit -Name "Servers" -DisplayName "Servers" -Path "OU=PlanA,DC=PlanA,DC=io"
        New-ADOrganizationalUnit -Name "Admins" -DisplayName "Admins" -Path "OU=PlanA,DC=PlanA,DC=io"

        New-ADUser -Name "Ian Philpot" -DisplayName "Ian Philpot" -SamAccountName "ian.philpot" -AccountPassword $using:pass -Path "OU=Users,OU=PlanA,DC=PlanA,DC=io" -Enabled:$true
        New-ADUser -Name "Admin Philpot" -DisplayName "Admin Philpot" -SamAccountName "admin.philpot" -AccountPassword $using:pass -Path "OU=Admins,OU=PlanA,DC=PlanA,DC=io" -Enabled:$true

        New-ADGroup -Name "Server Admins" -DisplayName "Server Admins" -SamAccountName "ServerAdmins" -GroupScope Global -Path "OU=Groups,OU=PlanA,DC=PlanA,DC=io"
        New-ADGroup -Name "Workstation Admins" -DisplayName "Workstation Admins" -SamAccountName "WorkstationAdmins" -GroupScope Global -Path "OU=Groups,OU=PlanA,DC=PlanA,DC=io"

        Add-ADGroupMember -Identity "Domain Admins" -Members admin.philpot -Confirm:$false

        Move-ADObject -Identity "CN=Adminian,CN=Users,DC=PlanA,DC=io" -TargetPath "OU=Admins,OU=PlanA,DC=PlanA,DC=io"
    }
}

#endregion

#region Step 4 PlanASQL

function CreatePlanASQL
{
    param($password = (Read-Host "What password would you like configure for the ADMINISTRATOR account?"))

    #Configure Azure Specifics
    $imageWin2k12 = (Get-AzureVMImage | ? {$_.Label -match "SQL Server 2012 SP1 Enterprise On Windows Server 2012"}).imagename
    $azureDnsIP = "10.10.2.4"

    #Configure machine specificsC8
    $instanceSize = @{"ExtraSmall" = "ExtraSmall"; "Small" = "Small"; "Medium" = "Medium"; "Large" = "Large"; "ExtraLarge" = "ExtraLarge"}
    $memberDNS = New-AzureDns -Name "PlanAMemberDNS" -IPAddress $azureDnsIP
    $machineName = "PlanASQL"
    $serviceName = "PlanA"

    #Setup Azure networking
    $location = @{"WestUS" = "West US"; "EastUS" = "East US"; "EastAsia" = "East Asia"; "SoutheastAsia" = "Southeast Asia"; "NorthEurope" = "North Europe"; "WestEurope" = "West Europe"}
    $affinityGroup = "PlanA"
    $virtualNetwork = "PlanANetwork"
    $subnet = "PlanASu"

    # SQL: Azure VM using default image
    $config = New-AzureVMConfig -Name $machineName -Label $machineName -ImageName $imageWin2k12 -InstanceSize $instanceSize.Large | 
        Add-AzureProvisioningConfig -WindowsDomain -AdminUsername "localadmin" -Password $password -JoinDomain "plana.io" -Domain "plana" -DomainUserName "adminian" -DomainPassword $password  |
        Set-AzureSubnet $subnet

    New-AzureVM -ServiceName $serviceName -VMs $config -VNetName $virtualNetwork -DnsSettings $memberDNS -WaitForBoot -Verbose
    Get-AzureVM $machineName | Set-AzureOSDisk -HostCaching ReadOnly
}

#endregion

#region Step 5 Configure SQL

function SQLSetupDisks
{
    Get-AzureVM -ServiceName PlanA -Name PlanASQL | Add-AzureDataDisk -CreateNew -DiskSizeInGB 127 -DiskLabel SQLData -LUN 1 | Update-AzureVM
    Get-AzureVM -ServiceName PlanA -Name PlanASQL | Add-AzureDataDisk -CreateNew -DiskSizeInGB 127 -DiskLabel SQLLogs -LUN 2 | Update-AzureVM
    Get-AzureVM -ServiceName PlanA -Name PlanASQL | Add-AzureDataDisk -CreateNew -DiskSizeInGB 127 -DiskLabel SQLBack -LUN 3 | Update-AzureVM
}

function SQLEnableCredSSP
{
    param($password = (Read-Host "What is the password for the ADMINISTRATOR account?"))

    $serviceName = "PlanA"
    $vmName = "PlanASQL"
    
    # Set Username
    $user = "plana\Adminian"

    # Set Password
    $pass = ConvertTo-SecureString $password -AsPlainText -Force

    # Create Credential
    $adminCredential = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $pass


	$uris = Get-AzureWinRMUri -ServiceName $serviceName -Name $vmName
    $maxRetry = 5
    For($retry = 0; $retry -le $maxRetry; $retry++)
    {
        Try
        {
	        Invoke-Command -ComputerName $uris[0].DnsSafeHost -Credential $adminCredential -Port $uris[0].Port -UseSSL `
		        -ScriptBlock {
		        Set-ExecutionPolicy Unrestricted -Force
		        $line = winrm g winrm/config/service/auth | Where-Object {$_.Contains('CredSSP = true')}
		        $isCredSSPServerEnabled = -not [string]::IsNullOrEmpty($line)
		        if(-not $isCredSSPServerEnabled)
		        {
		            Write-Host "Enabling CredSSP Server..."
			        winrm s winrm/config/service/auth '@{CredSSP="true"}'
			        Write-Host "CredSSP Server is enabled."
		        }
		        else
		        {
			        Write-Host "CredSSP Server is already enabled."
		        }
	        }
            break
        }
	    Catch [System.Exception]
	    {
		    Write-Host "Error - retrying..."
		    Start-Sleep 30
	    }
    }
    Write-Host "Pausing to Allow CredSSP to be enabled on $vmName"
    Start-Sleep 30
}

function EnterSQL
{
    param($password = (Read-Host "What is the password for the ADMINISTRATOR account?"))

    # Set Username
    $user = "planasql\localadmin"

    # Set Password
    $pass = ConvertTo-SecureString $password -AsPlainText -Force

    # Create Credential
    $cred = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $pass

    $uri = Get-AzureWinRMUri -ServiceName "PlanA" -Name "PlanASQL"

    Enter-PSSession -ComputerName $uri.Host -Port $uri.Port -Credential $cred -UseSSL -Authentication Credssp
}

Function FormatSQLDisks
{
	Param(
	[string]
	$serviceName = "PlanA",
	[string]
	$vmName = "PlanASQL",
	[string]
	$adminUserName = "plana\adminian",
	[string]
	$password = (Read-Host "What is the password for the ADMINISTRATOR account?")
	)

	################## Function execution begin ###########

	#Get the hosted service WinRM Uri
	$uris = Get-AzureWinRMUri -ServiceName $serviceName -Name $vmName

	$secPassword = ConvertTo-SecureString $password -AsPlainText -Force
	$credential = New-Object System.Management.Automation.PSCredential($adminUserName, $secPassword)

    $maxRetry = 5
    For($retry = 0; $retry -le $maxRetry; $retry++)
    {
        Try
        {
	        #Create a new remote ps session and pass in the scrip block to be executed
	        $session = New-PSSession -ComputerName $uris[0].DnsSafeHost -Credential $credential -Port $uris[0].Port -UseSSL 
	        Invoke-Command -Session $session -Scriptblock {
		
		        Set-ExecutionPolicy Unrestricted -Force

		        $drives = gwmi Win32_diskdrive
		        $scriptDisk = $Null
		        $script = $Null
		
		        #Iterate through all drives to find the uninitialized disk
		        foreach ($disk in $drives){
	    	        if ($disk.Partitions -eq "0"){
	                $driveNumber = $disk.DeviceID -replace '[\\\\\.\\physicaldrive]',''        
$script = @"
select disk $driveNumber
online disk noerr
attributes disk clear readonly noerr
create partition primary noerr
format quick
"@
			        }
			        $driveNumber = $Null
			        $scriptDisk += $script + "`n"
		        }
		        #output diskpart script
		        $scriptDisk | Out-File -Encoding ASCII -FilePath "c:\Diskpart.txt" 
		        #execute diskpart.exe with the diskpart script as input
		        diskpart.exe /s c:\Diskpart.txt

		        #assign letters and labels to initilized physical drives
		        $volumes = gwmi Win32_volume | where {$_.BootVolume -ne $True -and $_.SystemVolume -ne $True -and $_.DriveType -eq "3"}
		        $letters = 68..89 | ForEach-Object { ([char]$_)+":" }
		        $freeletters = $letters | Where-Object { 
	  		        (New-Object System.IO.DriveInfo($_)).DriveType -eq 'NoRootDirectory'
		        }
		        foreach ($volume in $volumes){
	    	        if ($volume.DriveLetter -eq $Null){
	        	        mountvol $freeletters[0] $volume.DeviceID
	    	        }
		        $freeletters = $letters | Where-Object { 
	    	        (New-Object System.IO.DriveInfo($_)).DriveType -eq 'NoRootDirectory'
		        }
		        }
	        }
	        #exit RPS session
	        Remove-PSSession $session
            break
        }
        Catch [System.Exception]
	    {
		    Write-Host "Error - retrying..."
		    Start-Sleep 30
	    }
    }
	################## Function execution end #############
}

function SQLConfigureLogin
{

    param($password = (Read-Host "What is the password for the ADMINISTRATOR account?"))

    # Set Username
    $user = "planasql\localadmin"

    # Set Password
    $pass = ConvertTo-SecureString $password -AsPlainText -Force

    # Create Credential
    $cred = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $pass

    $uri = Get-AzureWinRMUri -ServiceName "PlanA" -Name "PlanASQL"

    Invoke-Command -ComputerName $uri.Host -Port $uri.Port -Credential $cred -UseSSL -Authentication Credssp -ScriptBlock {
        $Username = "PlanA\Adminian"

        [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO') | out-null 
        $SqlServer = New-Object ('Microsoft.SqlServer.Management.Smo.Server') "localhost"
        $SqlUser = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Login -ArgumentList $SqlServer, "$Username"
        $SqlUser.LoginType = 'WindowsUser'
        $SqlUser.Create()
        $SqlUser.AddToRole('sysadmin')
    }
}

function SQLConfigureDefaultDisks
{
    param($password = (Read-Host "What is the password for the ADMINISTRATOR account?"))

    # Set Username
    $user = "plana\adminian"

    # Set Password
    $pass = ConvertTo-SecureString $password -AsPlainText -Force

    # Create Credential
    $cred = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $pass

    $uri = Get-AzureWinRMUri -ServiceName "PlanA" -Name "PlanASQL"

    Invoke-Command -ComputerName $uri.Host -Port $uri.Port -Credential $cred -UseSSL -Authentication Credssp -ScriptBlock {
        
        mkdir f:\data
        mkdir g:\logs
        mkdir h:\backup
        
        Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server\110\SDK\Assemblies\Microsoft.SqlServer.Smo.dll"

        $SqlServer = New-Object Microsoft.SqlServer.Management.Smo.Server("localhost")

        $SqlServer.DefaultFile = "F:\data"
        $SqlServer.DefaultLog = "G:\logs"
        $SqlServer.BackupDirectory = "H:\backup"
        $SqlServer.Alter() 

        Get-Service | ? {$_.Name -eq "MSSQLSERVER"} | Restart-Service
    }
}

function SQLSetupNetwork
{
    param($password = (Read-Host "What is the password for the ADMINISTRATOR account?"))

    # Set Username
    $user = "plana\adminian"

    # Set Password
    $pass = ConvertTo-SecureString $password -AsPlainText -Force

    # Create Credential
    $cred = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $pass

    $uri = Get-AzureWinRMUri -ServiceName "PlanA" -Name "PlanASQL"

    Invoke-Command -ComputerName $uri.Host -Port $uri.Port -Credential $cred -UseSSL -Authentication Credssp -ScriptBlock {
        if ((get-itemproperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQLServer\SuperSocketNetLib\Tcp').enabled -eq 0)
        {
	        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQLServer\SuperSocketNetLib\Tcp' -Name Enabled -Value 1
        }

        if ((get-itemproperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQLServer\SuperSocketNetLib\np').enabled -eq 0)
        {
	        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQLServer\SuperSocketNetLib\np' -Name Enabled -Value 1
        }

        Get-Service | ? {$_.Name -eq "MSSQLSERVER"} | Restart-Service
    }
}

function SQLSetupFirewall
{
    param($password = (Read-Host "What is the password for the ADMINISTRATOR account?"))

    # Set Username
    $user = "plana\adminian"

    # Set Password
    $pass = ConvertTo-SecureString $password -AsPlainText -Force

    # Create Credential
    $cred = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $pass

    $uri = Get-AzureWinRMUri -ServiceName "PlanA" -Name "PlanASQL"

    Invoke-Command -ComputerName $uri.Host -Port $uri.Port -Credential $cred -UseSSL -Authentication Credssp -ScriptBlock {

        #Rule Group Name
        $GroupName = "SQL Server"

        #SQL Server details
        $SQLPortLocal = 1433

        #WFE/APP Server
        $SQLBrowserPort = 1434

        #Rule for SQL Instance Port - SQL Port 1433 Inbound
        $RSQL = New-NetFirewallRule -DisplayName "SQL Server Communication (TCP-In)" `
            -Description "This rule opens the SQL Server communication port $($SQLLocalPort)" `
            -Direction Inbound -LocalPort $SQLPortLocal -Group $GroupName -Protocol TCP -Profile Domain -Action Allow

        #Rule for SQL Browser - UDP Port 1434 Inbound
        $RSQLBROWSER = New-NetFirewallRule -DisplayName "SQL Server Browser (UDP-In)" `
            -Description "This rule opens the SQL Server Browser UDP port $($SQLBrowserPort)" -Direction Inbound `
            -LocalPort $SQLBrowserPort -Group $GroupName -Protocol UDP -Profile Domain -Action Allow 
    }
}

#endregion

#region Step 6 PlanASP

function CreatePlanASP
{
    param($password = (Read-Host "What password would you like configure for the ADMINISTRATOR account?"))

    #Configure Azure Specifics
    $imageWin2k12 = (Get-AzureVMImage | ? {$_.Label -match "SharePoint Server 2013 Trial"}).imagename
    $azureDnsIP = "10.10.2.4"

    #Configure machine specificsC8
    $instanceSize = @{"ExtraSmall" = "ExtraSmall"; "Small" = "Small"; "Medium" = "Medium"; "Large" = "Large"; "ExtraLarge" = "ExtraLarge"}
    $memberDNS = New-AzureDns -Name "PlanAMemberDNS" -IPAddress $azureDnsIP
    $machineName = "PlanASP"
    $serviceName = "PlanA"

    #Setup Azure networking
    $location = @{"WestUS" = "West US"; "EastUS" = "East US"; "EastAsia" = "East Asia"; "SoutheastAsia" = "Southeast Asia"; "NorthEurope" = "North Europe"; "WestEurope" = "West Europe"}
    $affinityGroup = "PlanA"
    $virtualNetwork = "PlanANetwork"
    $subnet = "PlanASu"

    # SQL: Azure VM using default image
    $config = New-AzureVMConfig -Name $machineName -Label $machineName -ImageName $imageWin2k12 -InstanceSize $instanceSize.ExtraLarge | 
        Add-AzureProvisioningConfig -WindowsDomain -AdminUsername "localadmin" -Password $password -JoinDomain "plana.io" -Domain "plana" -DomainUserName "adminian" -DomainPassword $password  |
        Set-AzureSubnet $subnet

    New-AzureVM -ServiceName $serviceName -VMs $config -VNetName $virtualNetwork -DnsSettings $memberDNS -WaitForBoot -Verbose
    Get-AzureVM -ServiceName $serviceName -Name $machineName | Set-AzureOSDisk -HostCaching ReadOnly
    Get-AzureVM -ServiceName $serviceName -Name $machineName | Add-AzureEndpoint -Name "SharePoint" -PublicPort 80 -LocalPort 80 -Protocol tcp | Update-AzureVM
    Get-AzureVM -ServiceName $serviceName -Name $machineName | Add-AzureEndpoint -Name "SharePointCA" -PublicPort 2013 -LocalPort 2013 -Protocol tcp | Update-AzureVM
}

#endregion

#region Step 7 Configure SharePoint

function SPEnableCredSSP
{
    param($password = (Read-Host "What is the password for the ADMINISTRATOR account?"))

    $serviceName = "PlanA"
    $vmName = "PlanASP"
    
    # Set Username
    $user = "plana\Adminian"

    # Set Password
    $pass = ConvertTo-SecureString $password -AsPlainText -Force

    # Create Credential
    $adminCredential = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $pass


	$uris = Get-AzureWinRMUri -ServiceName $serviceName -Name $vmName
    $maxRetry = 5
    For($retry = 0; $retry -le $maxRetry; $retry++)
    {
        Try
        {
	        Invoke-Command -ComputerName $uris[0].DnsSafeHost -Credential $adminCredential -Port $uris[0].Port -UseSSL `
		        -ScriptBlock {
		        Set-ExecutionPolicy Unrestricted -Force
		        $line = winrm g winrm/config/service/auth | Where-Object {$_.Contains('CredSSP = true')}
		        $isCredSSPServerEnabled = -not [string]::IsNullOrEmpty($line)
		        if(-not $isCredSSPServerEnabled)
		        {
		            Write-Host "Enabling CredSSP Server..."
			        winrm s winrm/config/service/auth '@{CredSSP="true"}'
			        Write-Host "CredSSP Server is enabled."
		        }
		        else
		        {
			        Write-Host "CredSSP Server is already enabled."
		        }
	        }
            break
        }
	    Catch [System.Exception]
	    {
		    Write-Host "Error - retrying..."
		    Start-Sleep 30
	    }
    }
    Write-Host "Pausing to Allow CredSSP to be enabled on $vmName"
    Start-Sleep 30
}

function EnterSP
{
    param($password = (Read-Host "What is the password for the ADMINISTRATOR account?"))

    # Set Username
    $user = "plana\adminian"

    # Set Password
    $pass = ConvertTo-SecureString $password -AsPlainText -Force

    # Create Credential
    $cred = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $pass

    $uri = Get-AzureWinRMUri -ServiceName "PlanA" -Name "PlanASP"

    Enter-PSSession -ComputerName $uri.Host -Port $uri.Port -Credential $cred -UseSSL -Authentication Credssp
}

function SPConfigureFarm
{
    param($password = (Read-Host "What is the password for the ADMINISTRATOR account?"))

    # Set Username
    $user = "plana\adminian"

    # Set Password
    $pass = ConvertTo-SecureString $password -AsPlainText -Force

    # Create Credential
    $cred = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $pass

    $uri = Get-AzureWinRMUri -ServiceName "PlanA" -Name "PlanASP"

    Invoke-Command -ComputerName $uri.Host -Port $uri.Port -Credential $cred -UseSSL -Authentication Credssp -ScriptBlock {

        Add-PSSnapin microsoft.sharepoint.powershell

        New-SPConfigurationDatabase -DatabaseName "SharePoint2013_Config" -DatabaseServer "planasql.plana.io" -AdministrationContentDatabaseName "SharePoint2013_Admin_Content" `
            -Passphrase (ConvertTo-SecureString "Pass@word" -AsPlainText -Force) -FarmCredentials $using:cred

        Install-SPHelpCollection -All

        Initialize-SPResourceSecurity

        Install-SPService

        Install-SPFeature -AllExistingFeatures

        New-SPCentralAdministration -Port 2013 -WindowsAuthProvider "NTLM"

        Install-SPApplicationContent

        New-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name "DisableLoopbackCheck"  -value "1" -PropertyType dword

        New-SPAlternateUrl -WebApplication "http://planasp:2013" -Url "http://plana.cloudapp.net:2013" -Zone Internet
        New-SPAlternateUrl -WebApplication "http://planasp:2013" -Url "http://plana:2013" -Zone Intranet
    }
}

function SPConfigureServices
{
    param($password = (Read-Host "What is the password for the ADMINISTRATOR account?"))

    # Set Username
    $user = "plana\adminian"

    # Set Password
    $pass = ConvertTo-SecureString $password -AsPlainText -Force

    # Create Credential
    $cred = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $pass

    $uri = Get-AzureWinRMUri -ServiceName "PlanA" -Name "PlanASP"

    Invoke-Command -ComputerName $uri.Host -Port $uri.Port -Credential $cred -UseSSL -Authentication Credssp -ScriptBlock {

        Add-PSSnapin microsoft.sharepoint.powershell

        $service = Get-SPServiceInstance | where {$_.TypeName -eq "User Profile Service"}
        if ($service.Status -ne "Online") {
            Write-Host "Starting User Profile Service instance" -NoNewline
            $service | Start-SPServiceInstance | Out-Null
            while ($true) {
                Start-Sleep 2
                $svc = Get-SPServiceInstance | where {$_.TypeName -eq "User Profile Service"}
                if ($svc.Status -eq "Online") { break }
            }
        }

        $saAppPool = Get-SPServiceApplicationPool "SharePoint Web Services System" 
        New-SPProfileServiceApplication -Name "User Profile Service Application" -ApplicationPool $saAppPool -ProfileDBName "PlanA_UPA_Profile" -SocialDBName "PlanA_UPA_Social" -ProfileSyncDBName "PlanA_UPA_Sync"

        $svc = Get-SPServiceInstance | where {$_.TypeName -eq "User Profile Synchronization Service"}
        $app = Get-SPServiceApplication -Name "User Profile Service Application"

        if ($svc.Status -ne "Online") {
            Write-Host "Starting the User Profile Service Synchronization instance" -NoNewline
            $svc.Status = "Provisioning"
            $svc.IsProvisioned = $false
            $svc.UserProfileApplicationGuid = $app.Id
            $svc.Update()

            Write-Host "Setting Synchronization Server to $vmName"
            $app.SetSynchronizationMachine($vmName, $svc.Id, $spFarmUsername, $spFarmPassword)
          
            $svc | Start-SPServiceInstance | Out-Null
        }

        $accountName = $using:user
 
        $claimType = "http://schemas.microsoft.com/sharepoint/2009/08/claims/userlogonname"
        $claimValue = $accountName
        $claim = New-Object Microsoft.SharePoint.Administration.Claims.SPClaim($claimType, $claimValue, "http://www.w3.org/2001/XMLSchema#string", [Microsoft.SharePoint.Administration.Claims.SPOriginalIssuers]::Format("Windows"))
        $claim.ToEncodedString()
 
        $permission = [Microsoft.SharePoint.Administration.AccessControl.SPIisWebServiceApplicationRights]"FullControl"
 
        $SPAclAccessRule = [Type]"Microsoft.SharePoint.Administration.AccessControl.SPAclAccessRule``1"
        $specificSPAclAccessRule = $SPAclAccessRule.MakeGenericType([Type]"Microsoft.SharePoint.Administration.AccessControl.SPIisWebServiceApplicationRights")
        $ctor = $SpecificSPAclAccessRule.GetConstructor(@([Type]"Microsoft.SharePoint.Administration.Claims.SPClaim",[Type]"Microsoft.SharePoint.Administration.AccessControl.SPIisWebServiceApplicationRights"))
        $accessRule = $ctor.Invoke(@([Microsoft.SharePoint.Administration.Claims.SPClaim]$claim, $permission))
 
        $ups = Get-SPServiceApplication | ? { $_.TypeName -eq 'User Profile Service Application' }
        $accessControl = $ups.GetAccessControl()
        $accessControl.AddAccessRule($accessRule)
        $ups.SetAccessControl($accessControl)
        $ups.Update()

        $spServicesToStart = "Claims to Windows Token Service", "Access Service", "App Management Service", "Business Data Connectivity Service", "Excel Calculation Services", `
            "Managed Metadata Web Service", "Microsoft SharePoint Foundation Sandboxed Code Service", "Secure Store Service", "Microsoft SharePoint Foundation Web Application"

        Get-SPServiceInstance | 
            Where-Object {
	            $_.Server.Address -eq $env:COMPUTERNAME -and
	            $_.Status -ne 'Online' -and $_.TypeName -in $spServicesToStart} |
	            ForEach-Object {
	                Write-Host ("Starting Service Application {0}..." -f $_.TypeName)
	                Start-SPServiceInstance $_.Id
	                Write-Host "Service Application Started."
	            }
    }
}

function SPConfigureWeb
{
    param($password = (Read-Host "What is the password for the ADMINISTRATOR account?"))

    # Set Username
    $user = "plana\adminian"

    # Set Password
    $pass = ConvertTo-SecureString $password -AsPlainText -Force

    # Create Credential
    $cred = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $pass

    $uri = Get-AzureWinRMUri -ServiceName "PlanA" -Name "PlanASP"

    Invoke-Command -ComputerName $uri.Host -Port $uri.Port -Credential $cred -UseSSL -Authentication Credssp -ScriptBlock {

        Add-PSSnapin microsoft.sharepoint.powershell

        New-SPServiceApplicationPool -Name "SharePoint - 80" -Account "plana\adminian"
        $appPool = Get-SPServiceApplicationPool "SharePoint - 80"
        $account = Get-SPManagedAccount PLANA\adminian

        $authProvider = New-SPAuthenticationProvider -UseWindowsIntegratedAuthentication -UseBasicAuthentication
        New-SPWebApplication -Name "Test Web App" -URL http://planasp -Port 80 -ApplicationPool $appPool.name -ApplicationPoolAccount $account -AuthenticationProvider $authProvider
		New-SPSite -name "Playground" -url "http://planasp" -Template "STS#0" -OwnerAlias "adminian"
        New-SPAlternateUrl -WebApplication "http://planasp" -Url "http://plana.cloudapp.net" -Zone Default
    }
}

#endregion