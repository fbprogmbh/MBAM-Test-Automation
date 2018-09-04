<#
Copyright (c) 2017, FB Pro GmbH, Germany
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the <organization> nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#>

<#

    Author(s):        Dennis Esly
    Date:             02/02/2017
    Last change:      11/29/2017
    Version:          1.1

#>

#region Imports
Import-Module MbamExtensionModule -ErrorAction SilentlyContinue
Import-Module WinSrvExtensionModule -ErrorAction SilentlyContinue
Import-Module ADExtensionModule -ErrorAction SilentlyContinue
Import-Module LogFileModule -ErrorAction SilentlyContinue

# Load settings from setting file
Import-LocalizedData -FileName Settings.psd1 -BaseDirectory Settings -BindingVariable "ConfigFile"
#endregion

<#  
    Configuration
    =================================================================
#>

$mbamVersion = $ConfigFile.Settings.Mbam.Server.Version
$mbamUrl = "http://mbam.services.corp.fbpro"
$reportHtmlTitle = "FB Pro GmbH - MBAM-Server report " + (Get-Date -UFormat "%Y%m%d_%H%M") 

$year = Get-Date -Format "yyyy"
$month = Get-Date -Format "MM" 

$reportSavePath = $ConfigFile.Settings.Mbam.Server.ReportPath + "$year\$month\"
$xmlSavePath = $ConfigFile.Settings.Mbam.Server.XmlPath + "$year\$month\"


$modulePath = (Get-Module -ListAvailable MbamExtensionModule).Path
$modulePath = $modulePath.Substring(0,$modulePath.LastIndexOf('\'))

$advHelpDeskMembers = Get-Content "$modulePath\AdvHelpDeskMembers.txt"
$HelpDeskMembers = Get-Content "$modulePath\HelpDeskMembers.txt"
$ReportsROMembers = Get-Content "$modulePath\ReportsROMembers.txt"
$knownAdmins = Get-Content "$modulePath\knownLocalAdmins.txt"
$expectedLogins = Get-Content "$modulePath\expectedLogins.txt"
$webServerFeatureList = @(
        'Web-Static-Content', 
        'Web-Default-Doc',
        'Web-Asp-Net45', 
        'Web-Net-Ext45', 
        'Web-ISAPI-Ext', 
        'Web-ISAPI-Filter', 
        'Web-Windows-Auth', 
        'Web-Filtering')
$windowsServerFeatureList = @(
            'Net-Framework-45-Core', 
            'NET-WCF-HTTP-Activation45', 
            'NET-WCF-TCP-Activation45', 
            'WAS-Process-Model', 
            'WAS-NET-Environment', 
            'WAS-Config-APIs')
$serviceList = @(
        'WAS', 
        'W3SVC')
$aspNetMvc4 = @('Microsoft ASP.NET MVC 4 Runtime')
 
$fileDate = Get-Date -UFormat "%Y%m%d_%H%M"

<#
    Configuration for short system information in report
    ==============================================
#>
$reportDate = Get-Date -Format g
$currentHost = [System.Net.Dns]::GetHostByName(($env:computerName)) | select -ExpandProperty Hostname
$osInfo = Get-OperatingSystemInfo
$lastBootUpTime = Get-SystemStartupTime
$freeRAM = "{0:N3}" -f ($osInfo.FreePhysicalMemory/1MB)
$freeDiskSpace = "{0:N1}" -f ((get-WmiObject win32_logicaldisk | where DeviceID -eq "C:" | select -ExpandProperty FreeSpace)/1GB)
$logo = $ConfigFile.Settings.Logo
$updates = Get-FormattedUpdateInformation
$sccmUpdates = Get-FormattedSccmUpdateInformation
$restart =  Test-WinSrvRestartNescessary 
If (Get-PendingReboot) { $rebootPending = "yes" } else { $rebootPending = "no" }

<#
    Check and ensure necessary framework conditions
    ===================================================================

    Check conditions like existence of filepath for reports and xml files 
    and create it if necessary.
#>

# Test if path for saving report files exists, otherwise create it
if (!(test-path $reportSavePath))
{
    New-Item -Path $reportSavePath -ItemType Directory -Force
} 

# Test if path for saving XML files exists, otherwise create it
if (!(test-path $xmlSavePath))
{
    New-Item -Path $xmlSavePath -ItemType Directory -Force
}


<# 
    Run testcases and save the results in a variable
    =================================================================== 
#>

$mbamInfrastructureStatus = @(
    Test-WinSrvFirewallPort443State
    Test-MbamComplianceDbSrvConnection
    Test-MbamRecoveryDbSrvConnection
    Test-MbamComplianceDbConnectState
    Test-MbamRecoveryDbConnectState
)

$mbamOSStatus = @(
    Test-WinSrvFeatureState -feature "web-server" -moduleID "TC-MBAM-0018"
    Test-WinSrvFeatureState -feature $webServerfeatureList -moduleID "TC-MBAM-0019" 
    Test-WinSrvServiceState -service $serviceList -moduleId "TC-MBAM-0020"
    Test-WinSrvFeatureState -feature $windowsServerFeatureList -moduleID "TC-MBAM-0021" 
    Test-WinSrvSoftwareInstallState -softwareList $aspNetMvc4 -moduleId "TC-MBAM-0022"
    Test-WinSrvRestartedAfterUpdate -moduleId "TC-MBAM-0023"
    Test-WinSrvSccmClientUpdates -moduleID "TC-MBAM-0043"
    #Test-WinSrvMaintenanceModeOn -moduleID "TC-MBAM-0034" -pathToLogFile
)

$mbamApplicationStatus = @(
    Test-MbamSrvFeatureInstalled
    Test-MbamHelpDeskPage
    Test-MbamHelpDeskVirtualDir
    Test-MbamHelpDeskSPNState
    Test-MbamSelfServicePage
    Test-MbamSelfSvcVirtualDir -enabled
    Test-MbamSelfServiceSPNState
    Test-MbamServerVersion $mbamVersion
    Test-MbamSrvAgentSvcEnabled
    Test-MbamAdminPortalEnabled
    Test-MbamSelfSvcPortalEnabled -enabled
    Test-MbamHelpDeskPortalVersion $mbamVersion
    Test-MbamSelfSvcPortalVersion $mbamVersion -enabled
    Test-MbamSrvAgentSvcVersion $mbamVersion
    Test-MbamAdminSvcRunning -url $mbamUrl
    Test-MbamStatusReportSvcRunning -url $mbamUrl
    Test-MbamCoreSvcRunning -url $mbamUrl
    Test-ADSvcAccEnabled -identity $ConfigFile.Settings.Mbam.Server.ServiceAccount -type SamAccountName -moduleID "TC-MBAM-0058"
    Test-ADSvcAccPwdExpired -identity $ConfigFile.Settings.Mbam.Server.ServiceAccount -type SamAccountName
    Test-ADSvcAccPwdNeverExpires -identity $ConfigFile.Settings.Mbam.Server.ServiceAccount -type SamAccountName 
)


$mbamSecurityStatus = @(        
    Test-PkiCertificateValid -thumbprint $ConfigFile.Settings.Mbam.Server.CertificateThumbprint -hostname $ConfigFile.Settings.Mbam.Server.Hostname -moduleID "TC-MBAM-0033"
    Test-MbamCertificateThumbprint -thumbprint $ConfigFile.Settings.Mbam.Server.CertificateThumbprint
    Test-PkiCertificateExpirationDate -thumbprint $ConfigFile.Settings.Mbam.Server.CertificateThumbprint -moduleID "TC-MBAM-0039"
    Test-MbamHelpDeskSslOnly
    Test-MbamSelfServiceSslOnly  
    Test-ADSecurityGroupMember -securityGroup $ConfigFile.Settings.Mbam.Server.AdvHelpDesk -members $advHelpDeskMembers -moduleId "TC-MBAM-0035.1"  
    Test-ADSecurityGroupMember -securityGroup $ConfigFile.Settings.Mbam.Server.HelpDesk -members $HelpDeskMembers -moduleId "TC-MBAM-0035.2"  
    Test-ADSecurityGroupMember -securityGroup $ConfigFile.Settings.Mbam.Server.ReportGroup -members $ReportsROMembers -moduleId "TC-MBAM-0035.3"  
    Test-LocalAdmins -knownAdmins $knownAdmins -moduleID "TC-MBAM-0042"
    Test-LastUserLogins -acceptedUsers $expectedLogins
)

$mbamServerEnvironmentSystemsStatus = @(
    Test-ADDefaultDCConnection -moduleID "TC-MBAM-0047"
    Test-DNSServerConnection -moduleId "TC-MBAM-0046" 
    Test-ForestDCsConnection -moduleID "TC-MBAM-0048" -exceptionList $ConfigFile.Settings.WinSrv.dcExceptionList
)



<#  
    Build the report
    ====================================================================
#>
          
$report = "<!DOCTYPE html>
        <html>
            <head>
                <title>$reportHtmlTitle</title>
                <style>
                    html {margin: 0; padding: 0;}
                    body {font-size: 14px; margin: 0; padding: 0 0 10px 0;}
                    h1 {color: #fff;}
                    h1 span {text-transform: uppercase;}
                    h3 {margin-top: 40px; padding: 5px; max-width: 40%; text-transform: uppercase;}
                    h1, h2, h3, p, table, img {margin-left: 20px;}
                    ul {list-style-type: square; font-size: 16px;}
                    li {margin-top: 5px; padding: 3px;}
                    li:hover {background-color: #f2f2f2;}
                    li a {text-decoration: none; color: #000}
                    p {font-size: 16px;}
                    table, table.result-table {width: 90%; border: 1px solid darkgrey; border-collapse: collapse;font-family: Arial, sans-serif;}
                    table.info {max-width: 950px; border: 1px solid black; border-collapse: collapse;font-family: Courier, sans-serif;}
                    th {background-color: #d6d6c2; color: white; text-transform: uppercase; font-size: 1.5em; border-bottom: 1px solid darkgray;}
                    th, td {padding: 5px 10px; text-align: left;}
                    tr:nth-child(even) {background-color: #e6e6e6;}
                    tr:hover {background-color: #a6a6a6;}
                    table.result-table td:first-child {width: 15%}
                    table.result-table td:nth-child(2) {width: 50%;}
                    table.result-table td:nth-child(3) {width: 20%;}
                    table.result-table td:last-child {width: 15%;}
                    table.result-table th:last-child {text-align: center;}
                    table.info td:first-child {width: 250px;}
                    table.info td:last-child {width: 700px;}
                    table.info ul {padding-left: 15px;}
                    .header {background-color: #bfbfbf; width: 100%; padding: 20px 0;}
                    .header img {text-align: center;}
                    .passed, .green {background-color: #33cc33; color: #fff;}
                    .failed, .red {background-color: #cc0000; color: #fff;}
                    .warning, .orange {background-color: #ff9933; color: #fff;}
                    .green, .red, .orange {width: 25px; height: auto; display: inline-block; text-align: center;}
                    .hostname {color: #3366ff; font-weight: bold;}
                    span.passed, span.failed, span.warning {display: block; padding: 5px; border-radius: 30px; width: 25px; text-align: center; font-weight: bold; margin: auto;}
                </style>
            </head>
            <body>
                <div class=`"header`">
                    <img src=`"$logo`">
                    <h1><span>Microsoft Bitlocker</span> Administration and Monitoring</h1>
                </div>
                <h2>Server Status-Report</h2>

                <p>Report created at $reportDate on <span class=`"hostname`">$currentHost</span></p>"

# Add a navigation to the report 
$report += "<nav><ul>"
$report += New-MbamReportNavPoint -resultObjects $mbamInfrastructureStatus -navPointText "Infrastructure status" -anchor "1" 
$report += New-MbamReportNavPoint -resultObjects $mbamOSStatus -navPointText "Operating System status" -anchor "2" 
$report += New-MbamReportNavPoint -resultObjects $mbamApplicationStatus -navPointText "Application status" -anchor "3" 
$report += New-MbamReportNavPoint -resultObjects $mbamSecurityStatus -navPointText "Security Status" -anchor "4" 
$report += New-MbamReportNavPoint -resultObjects $mbamServerEnvironmentSystemsStatus -navPointText "Server Environment Systems Status" -anchor "5" 
$report += "<li><a href=`"#6`">User Login History</a></li>" 
$report += "<li><a href=`"#7`">Update History</a></li>" 
$report += "<li><a href=`"#8`">SCCM deployment history</a></li>"   
$report += "</ul></nav>"         

# Add a short system overview                
$report +=  "<table class=`"info`">
                <tr>
                    <td>Host:</td>
                    <td>$currentHost</span>
                </tr>
                <tr>
                    <td>Operating System:</td>
                    <td>"+$osInfo.Caption+"</span>
                </tr>
                <tr>
                    <td>OS version:</td>
                    <td>"+$osInfo.Version+"</span>
                        </tr>
                        <tr>
                            <td>Last boot up time:</td>
                            <td>$LastBootUpTime</span>
                        </tr>
                        <tr>
                            <td>OS architecture:</td>
                            <td>"+$osInfo.OSArchitecture+"</span>
                </tr>
                <tr>
                    <td>Free physical memory (GB):</td>
                    <td>$freeRAM</span>
                </tr> 
                <tr>
                    <td>Free disk space (GB):</td>
                    <td>$freeDiskSpace</span>
                </tr>  
                <tr>
                    <td>Last installed updates:</td>
                    <td>$updates</span>
                </tr>   
                <tr>
                    <td>Last installed applicable updates via SCCM:</td>
                    <td>$sccmUpdates</span>
                </tr>  
                <tr>
                    <td>System restart within next 7 days may be nescessary:</td>
                    <td>$restart</td>
                </tr>
                <tr>
                    <td>Reboot pending:</td>
                    <td>$rebootPending</td>
                </tr>                        
            </table>"
 
 try
{      
    
# Get infrastructure status      
$report += New-MbamReportSectionHeader -resultObjects $mbamInfrastructureStatus -headertext "Infrastructure status" -anchor "1"  
$report += $mbamInfrastructureStatus | ConvertTo-TapResultHtmlTable
        
# Get operating system status      
$report += New-MbamReportSectionHeader -resultObjects $mbamOSStatus -headertext "Operating System status" -anchor "2"      
$report += $mbamOSStatus | ConvertTo-TapResultHtmlTable
  
# Get Mbam appliciation status      
$report += New-MbamReportSectionHeader -resultObjects $mbamApplicationStatus -headertext "Application status" -anchor "3"      
$report += $mbamApplicationStatus | ConvertTo-TapResultHtmlTable      
        
# Get security status      
$report += New-MbamReportSectionHeader -resultObjects $mbamSecurityStatus -headertext "Security Status" -anchor "4"      
$report += $mbamSecurityStatus | ConvertTo-TapResultHtmlTable

# Get and output server environment systems status
$report += New-MbamReportSectionHeader -resultObjects $mbamServerEnvironmentSystemsStatus -headertext "Server Environment Systems Status:" -anchor "5"
$report += $mbamServerEnvironmentSystemsStatus | ConvertTo-TapResultHtmlTable         
     
$report += "</table></div>"
# Add user login history to report
$report += Get-UserLoginHistory | ConvertTo-Html -Head "" -PreContent "<h3 id=`"6`">User Login Histroy (last 7 days)</h3>"

# Add update history to report
$report += Get-UpdateHistory -number 20 | ConvertTo-Html -Head "" -PreContent "<h3 id=`"7`">Update History (last 20 installed updates)</h3>"

# Add SCCM deployment history to report
$report += Get-SccmDeploymentHistory -number 20 | ConvertTo-Html -Head "" -PreContent "<h3 id=`"8`">Deployment group history (last 20 assignments)</h3>"

# Closing html tags
$report += "</body></html>"


# Save the report 
$report > $reportSavePath"MbamWebserver_report_$fileDate.html"



<#  
    Save results in XML file
    ================================================================================
#>

$allResults = $mbamInfrastructureStatus + $mbamOSStatus + $mbamApplicationStatus + $mbamSecurityStatus + $mbamServerEnvironmentSystemsStatus

# If there are testresult objects, save them in a xml file
if($allResults)
{
    $allResults | Export-Clixml $xmlSavePath"MbamServer_Reportobjects_$fileDate.xml"
}


<#  
    Send error email 
    =================================================================================
#>
#Send-MbamEmailOnError -resultObjects $allResults

}

# Catch any occured error and write it to log file
catch 
{
    $msg = $_.Exception.toString()
    $msg += "; " + $_.ScriptStackTrace.toString()
    write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
}
