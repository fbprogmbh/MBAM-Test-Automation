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
    Last change:      05/23/2017
    Version:          1.0

#>

Import-Module MbamExtensionModule.psm1


<#  
    Configuration
    =================================================================
#>

$agentVersion = "2.5.1135.0"
$reportSavePath = "C:\ClientReports\"
$reportHtmlTitle = "FB Pro GmbH - MBAM-Client report " + (Get-Date -UFormat "%Y%m%d_%H%M")
#$gpoSource = "C:\gpo.xml" 

<#
    Configuration for short system information in report
    ==============================================
#>
$fileDate = Get-Date -UFormat "%Y%m%d_%H%M"
$reportDate = Get-Date -Format g
$currentHost = [System.Net.Dns]::GetHostByName(($env:computerName)) | select -ExpandProperty Hostname
$logo = $ConfigFile.Settings.Logo

<#
    Check and ensure necessary framework conditions
    ===================================================================

    Check conditions e.g. existence of filepath for reports 
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

$mbamSecurityStatus = @(
    Test-MbamOSDiskProtectionStatus
    Test-MbamDriveProtectionStatus
    Test-TPMFirmwareVul
)

$mbamApplicationStatus = @(
    Test-MbamClientSoftwareState
    Test-MbamClientAgentServiceState
    Test-BitlockerDriverVersion
    Test-MbamClientAgentVersion $agentVersion
    Test-MbamClient2ServerStatusReporting
    Test-MbamClient2ServerKeyReporting
)

$mbamInfrastructureStatus = @(
    Test-MbamTPMStatus
    Test-MbamTpmOwnerShip
    Test-MbamTpmVersion
)

$mbamGpoStatus = @(
    #Test-MbamGpo -source $gpoSource
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
                    .result-table tr:hover {background-color: #a6a6a6; border: 2px solid #c6ecd9;}
                    table.result-table td:first-child {width: 10%}
                    table.result-table td:nth-child(2) {width: 10%;}
                    table.result-table td:nth-child(3) {width: 45%;}
                    table.result-table td:nth-child(4) {width: 20%;}
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
$report += "<li><a href=`"#1`">System overview</a></li>" 
$report += "<li><a href=`"#2`">MBAM agent configuration</a></li>" 
$report += "<li><a href=`"#3`">PowerShell Version</a></li>"
$report += New-MbamReportNavPoint -resultObjects $mbamSecurityStatus -navPointText "Security Status" -anchor "4" 
$report += New-MbamReportNavPoint -resultObjects $mbamApplicationStatus -navPointText "Application status" -anchor "5" 
$report += New-MbamReportNavPoint -resultObjects $mbamInfrastructureStatus -navPointText "Infrastructure status" -anchor "6"
$report += New-MbamReportNavPoint -resultObjects $mbamGpoStatus -navPointText "GPO Status" -anchor "7" 
$report += "<li><a href=`"#7`">MBAM event logs</a></li>" 
$report += "</ul></nav>"         

# Add a short system overview 
$report += "<h3 id=`"1`">System overview</h3>"               
$report +=  Get-SystemOverview | ConvertTo-HtmlTable -cssClass info

# Add MBAM agent configuration overview
$report += "<h3 id=`"2`">MBAM agent configuration overview</h3>"
$report += Get-MbamClientConfiguration | ConvertTo-HtmlTable -cssClass info

# Add MBAM agent configuration overview
$report += "<h3 id=`"3`">PowerShell version overview</h3>"
$report += Get-PSVersionAsHtmlTable -cssClass info
 
 try
{   
# Get security status      
$report += New-MbamReportSectionHeader -resultObjects $mbamSecurityStatus -headertext "Security Status" -anchor "4"      
$report += $mbamSecurityStatus | ConvertTo-TapResultHtmlTable   

# Get MBAM appliciation status      
$report += New-MbamReportSectionHeader -resultObjects $mbamApplicationStatus -headertext "Application status" -anchor "5"      
$report += $mbamApplicationStatus | ConvertTo-TapResultHtmlTable  
    
# Get infrastructure status      
$report += New-MbamReportSectionHeader -resultObjects $mbamInfrastructureStatus -headertext "Infrastructure status" -anchor "6"  
$report += $mbamInfrastructureStatus | ConvertTo-TapResultHtmlTable
        
# Get GPO status      
$report += New-MbamReportSectionHeader -resultObjects $mbamGpoStatus -headertext "GPO status" -anchor "7"      
$report += $mbamGpoStatus | ConvertTo-TapResultHtmlTable

# Get latest 15 MBAM event log entries for admin and operational log
$report += "<h3 id='7'>MBAM event log entries</h3>"
$report += Get-MbamClientEventLogEntry -quantity 15

# Closing tags
$report += "</body></html>"


# Save the report 
$report > $reportSavePath"Mbam_report_$currentHost"_"$fileDate.html"

}
catch 
{
    $msg = $_.Exception.toString()
    $msg += "; " + $_.ScriptStackTrace.toString()
    write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
} 