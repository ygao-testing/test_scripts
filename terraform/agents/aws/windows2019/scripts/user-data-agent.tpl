<powershell>
mkdir "C:\Users\Administrator\cloud-init"
$log_path = "C:\Users\Administrator\cloud-init\log"
net user Administrator "${password}"
Add-MpPreference -ExclusionPath "C:\Users\Administrator"
$ComputerName = "${hostname}"

"1 Setting hostname" | Out-File -FilePath $log_path -Append

Remove-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "Hostname"
Remove-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "NV Hostname"

Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Computername\Computername" -name "Computername" -value $ComputerName
Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Computername\ActiveComputername" -name "Computername" -value $ComputerName
Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "Hostname" -value $ComputerName
Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "NV Hostname" -value  $ComputerName
Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "AltDefaultDomainName" -value $ComputerName
Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "DefaultDomainName" -value $ComputerName

"2 Download Agentless Test Files" | Out-File -FilePath $log_path -Append
%{ for os, libraries in jsondecode(AGENLTESS_TEST_FILES) }
%{ for library in libraries }
$remote_url = "https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/${os}/${library}"
$local = "C:\Users\Administrator\${library}"
Invoke-WebRequest -Uri $remote_url -OutFile $local | Out-File -FilePath $log_path -Append
Write-Host "Downloaded ${library} for ${os}"
%{ endfor }
%{ endfor }

"3 Download and install Notepad++ 8.4.1" | Out-File -FilePath $log_path -Append
$npp_installer_url = "https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/win-installers/npp.8.4.1.Installer.x64.exe"
$npp_installer_local = "C:\Users\Administrator\npp.installer.exe"
Invoke-WebRequest -Uri $npp_installer_url -OutFile $npp_installer_local
Start-Process -FilePath "$npp_installer_local" -ArgumentList "/S" -Wait | Out-File -FilePath $log_path -Append

"4 Download and install Python 3.12.0" | Out-File -FilePath $log_path -Append
$python_installer_url = "https://www.python.org/ftp/python/3.12.0/python-3.12.0rc2-amd64.exe"
$python_installer_local = "C:\Users\Administrator\python-amd64.exe"
Invoke-WebRequest -Uri $python_installer_url -OutFile $python_installer_local
Start-Process -FilePath "$python_installer_local" -ArgumentList "/quiet" -Wait | Out-File -FilePath $log_path -Append

"5 Download and install Git 2.44.0" | Out-File -FilePath $log_path -Append
$git_installer_url = "https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/win-installers/Git-2.44.0-rc1-64-bit.exe"
$git_installer_local = "C:\Users\Administrator\git.installer.exe"
Invoke-WebRequest -Uri $git_installer_url -OutFile $git_installer_local
Start-Process -FilePath "$git_installer_local" -ArgumentList "/VERYSILENT" -Wait | Out-File -FilePath $log_path -Append

"6 Download and install WinSCP 6.3.2" | Out-File -FilePath $log_path -Append
$wscp_installer_url = "https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/win-installers/WinSCP-6.3.2.msi"
$wscp_installer_local = "C:\Users\Administrator\wscp.installer.msi"
Invoke-WebRequest -Uri $wscp_installer_url -OutFile C:\Users\Administrator\wscp.installer.msi
Start-Process msiexec.exe -Wait -ArgumentList '/I C:\Users\Administrator\wscp.installer.msi /quiet' | Out-File -FilePath $log_path -Append

"7 Download and install Node.js 21.7.2" | Out-File -FilePath $log_path -Append
$node_installer_url = "https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/win-installers/node-v21.7.2-x64.msi"
Invoke-WebRequest -Uri $node_installer_url -OutFile C:\Users\Administrator\node.installer.msi
Start-Process msiexec.exe -Wait -ArgumentList '/I C:\Users\Administrator\node.installer.msi /quiet' | Out-File -FilePath $log_path -Append

"8 Create file with fake AWS credentials (Secrets are currently not supported for Windows)" | Out-File -FilePath $log_path -Append
mkdir "C:\Users\Administrator\.aws"
$aws_credentials = "[default]", "aws_access_key_id = AKWAZIRT5YWNAX3MZ6FB", "aws_secret_access_key = Fxx15o/preFvB67+OLkrFuzGLLYKNbDHazB8dR8t"
$aws_credentials | Out-File -FilePath "C:\Users\Administrator\.aws\credentials"

"9 Set-up WinRM" | Out-File -FilePath $log_path -Append
netsh advfirewall firewall add rule name="WINRM" dir=in action=allow protocol=TCP localport=5985
winrm quickconfig -q
winrm set "winrm/config/service" '@{AllowUnencrypted="true"}'
winrm set "winrm/config/service/auth" '@{Basic="true"}'

"10 Download and install Google Chrome 109.0.5414.12" | Out-File -FilePath $log_path -Append
$chrome_installer_url = "https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/win-installers/109.0.5414.120_chrome_installer.exe"
$chrome_installer_local = "C:\Users\Administrator\chrome.installer.exe"
Invoke-WebRequest -Uri $chrome_installer_url -OutFile $chrome_installer_local
"10.1 Running Chrome installer. Using 300 sec hard sleep instead of '-wait' because this installer hangs even after Chroms is already installed." | Out-File -FilePath $log_path -Append
Start-Process -FilePath "$chrome_installer_local" -ArgumentList '/silent /install'
Start-Sleep 300

"11 Check if Agent installation is required" | Out-File -FilePath $log_path -Append
if ("${AGENTLESS_SCAN}" -eq "false") {
  "11.1 Installing LW Agent" | Out-File -FilePath $log_path -Append
  Invoke-WebRequest -Uri https://updates.lacework.net/win-1.7.2.3973-2023-11-05-release-1.7.0-cc74651519014fec0f7502858b06895a4cf0d802/Install-LWDataCollector.ps1 -OutFile C:\Users\Administrator\Install-LWDataCollector.ps1 | Out-File -FilePath $log_path -Append
  & C:\Users\Administrator\Install-LWDataCollector.ps1 -MSIURL https://updates.lacework.net/windows/latest/LWDataCollector.msi -AccessToken "${agent_access_token}" -ServerURL https://aprodus2.agent.lacework.net | Out-File -FilePath $log_path -Append
}

"Done" | Out-File -FilePath $log_path -Append
</powershell>
