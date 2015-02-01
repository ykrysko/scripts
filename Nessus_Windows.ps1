##Windows7/2008R2 Nessus prep script

#Assign values to some variables below

$username = "xadministrator"  #The user account with administrative privileges to be used for scanning
$password = "QAZwsx!@#456QAZwsx" #Password for the above user account

#Let's go
$fwsrv =  Get-Service -Name "MpsSvc" | Where-Object {$_.status -eq "Stopped"}

if ( $fwsrv -eq $null ) {
Write-Host "Step #1. Modifying Windows Firewall rules" -ForegroundColor Red
sleep 5
$fwvalue = "advfirewall set store gpo=$env:COMPUTERNAME`r`nadvfirewall firewall add rule name=`"File and Printer Sharing (SMB-In)`" dir=in protocol=TCP localport=445 action=allow`r`
advfirewall firewall add rule name=`"File and Printer Sharing (NB-Session-In)`" dir=in protocol=TCP localport=139 action=allow`nadvfirewall firewall add rule name=`"Windows Management Instrumentation (ASync-In)`" dir=in protocol=TCP program=`"C:\Windows\system32\wbem\unsecapp.exe`" action=allow`r`
advfirewall firewall add rule name=`"Windows Management Instrumentation (DCOM-In)`" dir=in protocol=TCP localport=135 program=`"C:\Windows\system32\svchost.exe`" action=allow`r`
advfirewall firewall add rule name=`"Windows Management Instrumentation (WMI-In)`" dir=in protocol=TCP program=`"C:\Windows\system32\svchost.exe`" action=allow`n"
Set-Content -Value $fwvalue -Path .\firewall.txt
netsh -f .\firewall.txt
Remove-Item -Path .\firewall.txt
}
else { 
Write-Host "Step #1. Looks like Windows Firewall service is stopped. Skipping..." -ForegroundColor Red
}

Write-Host "Step #2. Enabling $username account and setting $password as password for it" -ForegroundColor Red
sleep 5

$user = Get-WmiObject Win32_UserAccount -filter "LocalAccount=True AND Name='$username'"
if ( $user -eq $null ) {
    net user "$username" "$password" /add /expires:never /passwordchg:no /yes
	net localgroup "Administrators" "$username" /add
}
else {
    net user "$username" "$password" /expires:never /passwordchg:no
	}
$group = net user $username | findstr /l "Administrators"	
if ( $group -eq $null ) {
	net localgroup "Administrators" "$username" /add
}
$userd = Get-WmiObject Win32_UserAccount -filter "LocalAccount=True AND Name='$username'" | Select-Object Disabled
if ( $userd -ne $null ) {
	net user "$username" /active:yes
}

Write-Host "Step #3. Enabling administrative shares on $env:COMPUTERNAME" -ForegroundColor Red
sleep 5

function Test-Regedit {

param (

 [parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]$Path,

[parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]$Value
)

try {
Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
 return $true
 }

catch {
return $false

	}
}

if ($(Test-Regedit -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Value 'AutoShareServer') -eq $true) {
	Remove-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -Name "AutoShareServer"
}
if ($(Test-Regedit -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Value 'AutoShareWks') -eq $true) {
	Remove-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -Name "AutoShareWks"
}
if ($(Test-Regedit -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Value 'LocalAccountTokenFilterPolicy') -eq $true) {
	Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -Force
}
else {
	New-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -PropertyType "DWORD" -Force
}

Write-Host "`nFinished messing with $env:COMPUTERNAME. Rebooting...`n" -ForegroundColor Green
	sleep 5
#Restart-Computer -Force