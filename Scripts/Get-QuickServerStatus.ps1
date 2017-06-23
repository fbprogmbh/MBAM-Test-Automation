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
    Date:             04/17/2017
    Last change:      06/23/2017
    Version:          1.0

#>


Import-Module MbamExtensionModule.psm1

<#  
    Configuration
    =================================================================
#>

$mbamVersion = "2.5.1133.0"

$year = Get-Date -Format "yyyy"
$month = Get-Date -Format "MM" 

$reportSavePath = "C:\inetpub\wwwroot\reports\Reports\$year\$month\"
$fileDate = Get-Date -UFormat "%Y%m%d_%H%M"
 

$reportHtmlTitle = "FB Pro GmbH - MBAM-Server quick report " + (Get-Date -UFormat "%Y%m%d_%H%M") 

$modulePath = (Get-Module -ListAvailable MbamExtensionModule).Path
$modulePath = $modulePath.Substring(0,$modulePath.LastIndexOf('\'))

$advHelpDeskMembers = Get-Content "$modulePath\AdvHelpDeskMembers.txt"
$HelpDeskMembers = Get-Content "$modulePath\HelpDeskMembers.txt"
$ReportsROMembers = Get-Content "$modulePath\ReportsROMembers.txt"
$knownAdmins = Get-Content "$modulePath\knownLocalAdmins.txt"
$expectedLogins = Get-Content "$modulePath\expectedLogins.txt"


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


<# 
    Run testcases and save the results in a variable
    =================================================================== 
#>

$mbamInfrastructureStatus = @(
    Test-MbamFirewallPortState
    Test-MbamComplianceDbServerConnection
    Test-MbamRecoveryDbServerConnection
    Test-MbamComplianceDbConnectState
    Test-MbamRecoveryDbConnectState
)

$mbamOSStatus = @(
    Test-MbamWebServerRoleState 
    Test-MbamWebserverServiceState
    Test-MbamWindowsFeatureState 
    Test-MbamWebserverFeatureState 
    Test-MbamASP_NetMVC4
    Test-MbamServerRestartedAfterUpdate
    Test-SccmClientUpdates
)

$mbamApplicationStatus = @(
    Test-MbamHelpDeskPage -https
    Test-MbamSelfServicePage -https
    Test-MbamHelpDeskSPNState
    Test-MbamSelfServiceSPNState
    Test-MbamServerVersion25 $mbamVersion
)

$mbamSecurityStatus = @(        
    Test-MbamCertificateValidationState
    Test-MbamCertificateThumbprint -thumbprint $ConfigFile.Settings.CertificateThumbprint
    Test-MbamSSLCertificateExpirationDate
    Test-MbamHelpDeskSslOnly
    Test-MbamSelfServiceSslOnly    
    Test-MbamSecurityGrpMembers -members $advHelpDeskMembers -group AdvHelpDesk
    Test-MbamSecurityGrpMembers -members $HelpDeskMembers -group HelpDesk
    Test-MbamSecurityGrpMembers -members $ReportsROMembers -group ReportsRO
    Test-LocalAdmins -knownAdmins $knownAdmins
)

$mbamServerEnvironmentSystemsStatus = @(
    Test-DefaultDCConnection
    Test-DNSServerConnection
    Test-ForestDCsConnection
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
$report += $mbamInfrastructureStatus | ConvertTo-HtmlTable
        
# Get operating system status      
$report += New-MbamReportSectionHeader -resultObjects $mbamOSStatus -headertext "Operating System status" -anchor "2"      
$report += $mbamOSStatus | ConvertTo-HtmlTable
  
# Get Mbam appliciation status      
$report += New-MbamReportSectionHeader -resultObjects $mbamApplicationStatus -headertext "Application status" -anchor "3"      
$report += $mbamApplicationStatus | ConvertTo-HtmlTable      
        
# Get security status      
$report += New-MbamReportSectionHeader -resultObjects $mbamSecurityStatus -headertext "Security Status" -anchor "4"      
$report += $mbamSecurityStatus | ConvertTo-HtmlTable

# Get and output server environment systems status
$report += New-MbamReportSectionHeader -resultObjects $mbamServerEnvironmentSystemsStatus -headertext "Server Environment Systems Status:" -anchor "5"
$report += $mbamServerEnvironmentSystemsStatus | ConvertTo-HtmlTable         

# Closing html tags
$report += "</body></html>"


# Save the report 
$report > $reportSavePath"MbamWebserver_report_$fileDate.html"

}

# Catch any occured error and write it to log file
catch 
{
    $msg = $_.Exception.toString()
    $msg += "; " + $_.ScriptStackTrace.toString()
    write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
}