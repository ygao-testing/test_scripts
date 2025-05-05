$Password = ConvertTo-SecureString "${password}" -AsPlainText -Force
New-LocalUser -Name "${username}" -Password $Password -FullName "${username}" -Description "Created by Terraform" -AccountNeverExpires -PasswordNeverExpires
Add-LocalGroupMember -Group "Administrators" -Member "${username}"

mkdir "C:\Users\${username}\cloud-init"
$log_path = "C:\Users\${username}\cloud-init\log"

"0.1 start" | Out-File -FilePath $log_path -Append

Add-MpPreference -ExclusionPath "C:\Users\${username}"

"2 Download Agentless Test Files" | Out-File -FilePath $log_path -Append
foreach ($os in $AGENTLESS_TEST_FILES.Keys) {
    foreach ($library in $AGENTLESS_TEST_FILES[$os]) {
        $remote_url = "https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/$os/$library"
        $local = "C:\Users\${username}\$library"
        Invoke-WebRequest -Uri $remote_url -OutFile $local | Out-File -FilePath $log_path -Append
        Write-Host "Downloaded $library for $os"
    }
}

"3 Download and install Notepad++ 8.4.1" | Out-File -FilePath $log_path -Append
$npp_installer_url = "https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/win-installers/npp.8.4.1.Installer.x64.exe"
$npp_installer_local = "C:\Users\${username}\npp.installer.exe"
Invoke-WebRequest -Uri $npp_installer_url -OutFile $npp_installer_local
Start-Process -FilePath "$npp_installer_local" -ArgumentList "/S" -Wait | Out-File -FilePath $log_path -Append

"4 Download and install Python 3.12.0" | Out-File -FilePath $log_path -Append
$python_installer_url = "https://www.python.org/ftp/python/3.12.0/python-3.12.0rc2-amd64.exe"
$python_installer_local = "C:\Users\${username}\python-amd64.exe"
Invoke-WebRequest -Uri $python_installer_url -OutFile $python_installer_local
Start-Process -FilePath "$python_installer_local" -ArgumentList "/quiet" -Wait | Out-File -FilePath $log_path -Append

"5 Download and install Git 2.44.0" | Out-File -FilePath $log_path -Append
$git_installer_url = "https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/win-installers/Git-2.44.0-rc1-64-bit.exe"
$git_installer_local = "C:\Users\${username}\git.installer.exe"
Invoke-WebRequest -Uri $git_installer_url -OutFile $git_installer_local
Start-Process -FilePath "$git_installer_local" -ArgumentList "/VERYSILENT" -Wait | Out-File -FilePath $log_path -Append

"6 Download and install WinSCP 6.3.2" | Out-File -FilePath $log_path -Append
$wscp_installer_url = "https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/win-installers/WinSCP-6.3.2.msi"
$wscp_installer_local = "C:\Users\${username}\wscp.installer.msi"
Invoke-WebRequest -Uri $wscp_installer_url -OutFile C:\Users\${username}\wscp.installer.msi
Start-Process msiexec.exe -Wait -ArgumentList '/I C:\Users\${username}\wscp.installer.msi /quiet' | Out-File -FilePath $log_path -Append

"7 Download and install Node.js 21.7.2" | Out-File -FilePath $log_path -Append
$node_installer_url = "https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/win-installers/node-v21.7.2-x64.msi"
Invoke-WebRequest -Uri $node_installer_url -OutFile C:\Users\${username}\node.installer.msi
Start-Process msiexec.exe -Wait -ArgumentList '/I C:\Users\${username}\node.installer.msi /quiet' | Out-File -FilePath $log_path -Append

"8 Set-up WinRM" | Out-File -FilePath $log_path -Append
netsh advfirewall firewall add rule name="WINRM" dir=in action=allow protocol=TCP localport=5985
winrm quickconfig -q
winrm set "winrm/config/service" '@{AllowUnencrypted="true"}'
winrm set "winrm/config/service/auth" '@{Basic="true"}'

"9 Download and install Google Chrome 109.0.5414.12" | Out-File -FilePath $log_path -Append
$chrome_installer_url = "https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/win-installers/109.0.5414.120_chrome_installer.exe"
$chrome_installer_local = "C:\Users\${username}\chrome.installer.exe"
Invoke-WebRequest -Uri $chrome_installer_url -OutFile $chrome_installer_local
"9.1 Running Chrome installer. Using 300 sec hard sleep instead of '-wait' because this installer hangs even after Chroms is already installed." | Out-File -FilePath $log_path -Append
Start-Process -FilePath "$chrome_installer_local" -ArgumentList '/silent /install'
Start-Sleep 300

"10 Check if Agent installation is required" | Out-File -FilePath $log_path -Append

if ("${agentless_scan}" -eq "false") {
  "11.1 Installing LW Agent" | Out-File -FilePath $log_path -Append
  Invoke-WebRequest -Uri https://updates.lacework.net/win-1.7.2.3973-2023-11-05-release-1.7.0-cc74651519014fec0f7502858b06895a4cf0d802/Install-LWDataCollector.ps1 -OutFile C:\Users\${username}\Install-LWDataCollector.ps1 | Out-File -FilePath $log_path -Append
  & C:\Users\${username}\Install-LWDataCollector.ps1 -MSIURL https://updates.lacework.net/windows/latest/LWDataCollector.msi -AccessToken "${agent_access_token}" -ServerURL https://aprodus2.agent.lacework.net | Out-File -FilePath $log_path -Append
}

"Done" | Out-File -FilePath $log_path -Append
