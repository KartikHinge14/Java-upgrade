$server = get-content server.txt
foreach($node in $server){

invoke-command -cn $server -scriptblock{

$uninstall = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Get-ItemProperty | Where-Object {$_.DisplayName -like '*Java *' -or $_.DisplayName -like '*J2SE*' -or $_.DisplayName -like '*Java(TM) *' -and $_.DisplayName -ne 'Java Auto Updater' -and ($_.Publisher -like '*Oracle*' -or $_.Publisher -like '*Sun*') -and $_.Publisher -ne '' } | Select-Object uninstallstring,InstallLocation,DisplayName,DisplayVersion
    ForEach($ustr in $Uninstall){
        echo $ustr.DisplayName$ustr.InstallLocation================= >> c:\JavaPreviousVersion.txt
        $ustr=$ustr.UninstallString -Replace ('msiexec.exe','') -Replace ('msiexec','') -Replace ('/I','') -Replace ('/X','') -Replace ('/q','')
        $ustr=$ustr.trim()
        
      
        Start-Process C:\Windows\System32\msiexec.exe -ArgumentList "/x $ustr /qn /norestart" -wait  
        
        }
        
        
        
        
        
        
        
        
