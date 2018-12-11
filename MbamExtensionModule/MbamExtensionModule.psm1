<#
Copyright (c) 2018, FB Pro GmbH, Germany
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
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANYM
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#>

#region Author, date, version 
#
#    Author(s):        Dennis Esly | dennis.esly@fb-pro.com
#    Date:             05/03/2018
#    Last change:      11/12/2018
#    Version:          2.0.2
#    State:            Approved
#
#endregion

#region Imports
Using module TapResultClass

Import-Module Microsoft.PowerShell.Security -ErrorAction SilentlyContinue
Import-Module Microsoft.MBAM -ErrorAction SilentlyContinue
Import-Module ActiveDirectory -ErrorAction SilentlyContinue
Import-Module BitLocker -ErrorAction SilentlyContinue
Import-Module TrustedPlatformModule -ErrorAction SilentlyContinue
Import-Module LogFileModule -ErrorAction SilentlyContinue
Import-Module WinSrvExtensionModule -ErrorAction SilentlyContinue

# Load settings from setting file
$mbamExtensionModulePath = (Get-Module -ListAvailable MbamExtensionModule).Path
$baseDir = (Get-Item $mbamExtensionModulePath).Directory.Parent.Fullname+"\Settings"
Import-LocalizedData -FileName Settings.psd1 -BaseDirectory $baseDir -BindingVariable "ConfigFile"
#endregion

#region Set log file settings

# Set the path and name of standard log file to path and name configured in settings
$LogPath = $ConfigFile.Settings.LogFilePath
$LogName = (Get-date -Format "yyyyMMdd")+"_" + $ConfigFile.Settings.LogFileName

#endregion

#region Table of content
# ================
#
# 1 .........Test functions (public)
#
#   1.1 .....MBAM server tests
#
#   1.2 .....MBAM client tests
#
# 2 .........Helper functions
#
#   2.1 .....Client specific helpers
#
#   2.2 .....Server specific helpers
#
# 3 .........Report functions
# 
#   3.1 .....Client specific report functions
#
#   3.2 .....Server specific report functions
#
#   3.3 .....General report functions
#
# -----------------
#endregion


#region 1 Test functions
# ----------------------
#
# Section for all Test-* functions inside this module.
#
############################################################## 

#region 1.1 MBAM server tests
# ---------------------
#
# Section for tests targeting the MBAM backend service
#=====================================================

function Test-MbamComplianceDbConnectState
{
<#
.Synopsis
    Tests wether the administration-website application was found and successfully connected to the compliance database
.DESCRIPTION
    Tests wether the administration-website application was found and successfully connected to the compliance database.
    Therefore the last system startup is determined and afterwards the event log of MBAM-web/operational is checked for an event with ID 200 that contains the expression "Compliance database" in the message.
    Until the website is not access since the last system reboot, no event log records will be created and therefore the function will return a PSCustomObject with status "not found".
.EXAMPLE
    PS C:\Test-MBAMComplianceDbConnectState

    ID       : FBP-MBAM-0001
    moduleID : TC-MBAM-0001
    Task     : Administration-website application found and successfully connected to compliance database
    Status   : Connected
    Passed   : Passed
.NOTES
    ID FBP-MBAM-0001   
#>
[CmdletBinding()]
Param()

    $obj = [TapResult]::New("FBP-MBAM-0001", "TC-MBAM-0001", "Administration-website application found and successfully connected to compliance database")

    Write-Verbose "[FBP-MBAM-0001]: Get last system startup time"    
    $lastStartup = Get-SystemStartupTime

    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[FBP-MBAM-0001]" + [System.Environment]::NewLine
    $messageBag += "Module ID: [TC-MBAM-0001]"

    try
    {
        # In case the HelpDesk webpage was not called since the last system startup, we trigger a simple call to it, but without a output.
        # After that the event we will be looking for in the event log should be created, otherwise there is something wrong
        Test-MBAMHelpDeskPage | Out-Null

        Write-Verbose "[FBP-MBAM-0001]: Get MBAM event 200 after last system start up"
        $connected = Get-WinEvent -FilterHashtable @{logname="microsoft-windows-MBAM-web/operational";StartTime=$lastStartup;} -ErrorAction Stop | Where-Object {$_.Message -Like "*Compliance database*" -and $_.ID -eq 200} 

        if ($null -ne $connected)
        {
            # Event was found and connection to database was once established
            $obj.Status = "Connected"
            $obj.Passed = 1
        }
        else 
        {
            # Event still not found, something could be wrong.
            $obj.Status = "Not connected"
            $obj.Passed = 2

            $msg = "Event 200 not found: The MBAM administration website application is not connected to a supported version of the Compliance database. For further debugging look for Event 105 in Microsoft-Windows-MBAM-Web/Admin"+[System.Environment]::NewLine
            $msg += $messageBag
            Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 1 -EntryType Error -Category 0 
        }
    }
    catch 
    {
        $obj.Status = "Not found"
        $obj.Passed = 4

        $msg = "An error occured getting event id 200 information"+[System.Environment]::NewLine
        $msg += $messageBag
        Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 2 -EntryType Error -Category 0 
        Write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error
    }

    Write-Output $obj
}

function Test-MbamRecoveryDbConnectState
{
<#
.Synopsis
    Tests wether the administration-website application was found and successfully connected to the recovery database
.DESCRIPTION
    Tests wether the administration-website application was found and successfully connected to the recovery database.
    Therefore the last system startup is determined and afterwards the event log of MBAM-web/operational is checked for an event with ID 200 that contains the expression "Recovery database" in the message.
    Until the website is not access since the last system reboot, no event log record will be created and therefore the function will return a PSCustomObject with status "not found".
.OUTPUTS
    PSCustomObject
.EXAMPLE
    PS C:\> Test-MBAMRecoveryDbConnectState

    ID       : FBP-MBAM-0002
    moduleID : TC-MBAM-0002
    Task     : Administration-website application found and successfully connected to recovery database
    Status   : Connected
Passed   : Passed
.NOTES
    ID FBP-MBAM-0002
#>
[CmdletBinding()]
Param()

    $obj = [TapResult]::New("FBP-MBAM-0002", "TC-MBAM-0002", "Administration-website application found and successfully connected to recovery database")
    
    Write-Verbose "[FBP-MBAM-0002]: Get last system startup time"      
    $lastStartup = Get-SystemStartupTime

    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[FBP-MBAM-0002]" + [System.Environment]::NewLine
    $messageBag += "Module ID: [TC-MBAM-0002]"

    try 
    {
        # In case the HelpDesk webpage was not called since the last system startup, we trigger a simple call to it, but without a output.
        # After that the event we will be looking for in the event log should be created, otherwise there is something wrong
        Test-MBAMHelpDeskPage | Out-Null

        Write-Verbose "[FBP-MBAM-0002]: Get MBAM event 200 after last system start up"
        $connected = Get-WinEvent -FilterHashtable @{logname="microsoft-windows-MBAM-web/operational";StartTime=$lastStartup;} -ErrorAction Stop | Where-Object {$_.Message -Like "*Recovery database*" -and $_.ID -eq 200}

        if ($null -ne $connected)
        {  
            # Event was found and connection to database was once established
            $obj.Status = "Connected"
            $obj.Passed = 1
        }
        else 
        {
            # Event still not found, something could be wrong.
            $obj.Status = "Not connected"
            $obj.Passed = 2

            $msg = "Event 200 not found: The MBAM administration website application is not connected to a supported version of the Recovery database. For further debugging look for Event 105 in Microsoft-Windows-MBAM-Web/Admin"+[System.Environment]::NewLine
            $msg += $messageBag
            Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 1 -EntryType Error -Category 0 
        }
    }
    catch
    {
        $obj.Status = "Not found"
        $obj.Passed = 4

        $msg = "An error occured getting event id 200 information"+[System.Environment]::NewLine
        $msg += $messageBag
        Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 2 -EntryType Error -Category 0 
        Write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error 
    }

    Write-Output $obj    
}

function Test-MbamHelpDeskSPNState
{
<#
.Synopsis
    Tests if the HelpDesk has its Service Principal Name registered successfully.
.DESCRIPTION
    Tests if the HelpDesk has its Service Principal Name registered successfully. Therefore the event log is checked for a record with ID 202 and message containing the phrase "HelpDesk" 
    which was created after last system startup. If the HelpDesk website is not access since last startup, no record is created and the function will return "Not registered" 
.EXAMPLE
    PS C:\> Test-MBAMHelpDeskSPNState

    ID       : FBP-MBAM-0005
    moduleID : TC-MBAM-0004
    Task     : HelpDesk has its Service Principal Name registered successfully
    Status   : Registered
    Passed   : Passed
.NOTES
    ID FBP-MBAM-0005
#>  
[cmdletBinding()]
Param()
    
    $obj = [TapResult]::New("FBP-MBAM-0005", "TC-MBAM-0004", "HelpDesk has its Service Principal Name registered successfully")

    Write-Verbose "[FBP-MBAM-0005]: Get last system startup time"    
    $lastStartup = Get-SystemStartupTime

    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[FBP-MBAM-0005]" + [System.Environment]::NewLine
    $messageBag += "Module ID: [TC-MBAM-0004]"

    try
    {
        Write-Verbose "[FBP-MBAM-0005]: Searching for SPN registration event"
        Get-WinEvent -FilterHashtable @{logname="microsoft-windows-MBAM-web/operational";StartTime=$lastStartup;} `
            -ErrorAction stop | Where-Object {$_.Message -Like "*HelpDesk*" -and $_.ID -eq 202} | Out-Null

        # Set status, if no log record was found, an ObjectNotFound exception is thrown
        $obj.Status = "Registered"
        $obj.Passed = 1 
    }
    catch
    {
        # No registration logged since last startup
        $obj.Status = "Not found"
        $obj.Passed = 2

        $msg = "Event 202 not found: The MBAM /HelpDesk has not registered its SPNs correctly."+[System.Environment]::NewLine
        $msg += $messageBag
        Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 3 -EntryType Error -Category 0 
        Write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error
    }

    Write-Output $obj
}

function Test-MbamSelfServiceSPNState
{
<#
.SYNOPSIS
    Tests if the SelfService Portal has its Service Principal Name registered successfully.
.DESCRIPTION
    Tests if the SelfService Portal has its Service Principal Name registered successfully. Therefore the event log is checked for a record with ID 202 and message containing the phrase "SelfService" 
    which was created after last system startup. If the HelpDesk website is not access since last startup, no record is created and the function will return a PSCustomObject with status "Not found". 
.EXAMPLE
    PS C:\Workspace\ipd\Sources\MbamExtensionModule> Test-MBAMSelfServiceSPNState

    ID       : FBP-MBAM-0006
    moduleID : TC-MBAM-0005
    Task     : SelfService Portal has its Service Principal Name registered successfully
    Status   : Registered
    Passed   : Passed
.NOTES
    ID        FBP-MBAM-0006
    moduleID  TC-MBAM-0005
#>
[CmdletBinding()]
Param()   

    $obj = [TapResult]::New("FBP-MBAM-0006", "TC-MBAM-0005", "SelfService Portal has its Service Principal Name registered successfully")
    
    Write-Verbose "[FBP-MBAM-0006]: Get last system startup time"    
    $lastStartup = Get-SystemStartupTime

    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[FBP-MBAM-0006]" + [System.Environment]::NewLine
    $messageBag += "Module ID: [TC-MBAM-0005]"

    try
    {
        Write-Verbose "[FBP-MBAM-0006]: Searching for SPN registration event"
        Get-WinEvent -FilterHashtable @{logname="microsoft-windows-MBAM-web/operational";StartTime=$lastStartup;} `
            -ErrorAction stop | Where-Object {$_.Message -Like "*SelfService*" -and $_.ID -eq 202} | Out-Null

        # Set status, if no log record was found, an ObjectNotFound exception is thrown
        $obj.Status = "Registered"
        $obj.Passed = 1
            
    }
    catch
    {
        # No registration logged since last startup
        $obj.Status = "Not found"
        $obj.Passed = 2

        $msg = "Event 202 not found: The MBAM /SelfServcie has not registered its SPNs correctly."+[System.Environment]::NewLine
        $msg += $messageBag
        Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 3 -EntryType Error -Category 0 
        Write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error
    }

    Write-Output $obj
}

function Test-MbamAdminSvcRunning
{
<#
.SYNOPSIS
    Tests if the MBAM admin web service is running.
.DESCRIPTION
    Tests if the MBAM admin web service is running. As we need credentials to load the web service we only request the service and check the answer for a 401 forbidden.
    With a 401 we asume the service is up and running.
.PARAMETER url
    URL of the MBAM server including http:// or https://
.EXAMPLE
    PS C:\> Test-MbamAdminSvcRunning -url http://mbam.services.corp.fbpro/

    ID       : FBP-MBAM-0007
    moduleID : TC-MBAM-0006
    Task     : Webservice AdministrationService.svc running
    Status   : Running
    Passed   : Passed
.NOTES
    ID        FBP-MBAM-0007
    moduleID  TC-MBAM-0006
#>
[CmdletBinding()]
Param(
    [string]$url
)   

    Test-MBAMWCFServiceState -serviceType admin -uri $url -id FBP-MBAM-0007 -moduleId TC-MBAM-0006
}

function Test-MbamUserSvcRunning
{
<#
.SYNOPSIS
    Tests if the MBAM user web service is running.
.DESCRIPTION
    Tests if the MBAM user web service is running. As we need credentials to load the web service we only request the service and check the answer for a 401 forbidden.
    With a 401 we asume the service is up and running.
.PARAMETER url
    URL of the MBAM server including http:// or https://
.EXAMPLE
    PS C:\> Test-MbamUserSvcRunning -url http://mbam.service.corp.fbpro

    ID       : FBP-MBAM-0008
    moduleID : TC-MBAM-0007
    Task     : Webservice UserSupportService.svc running
    Status   : Not running
    Passed   : Failed
.NOTES
    ID        FBP-MBAM-0008
    moduleID  TC-MBAM-0007
#>
[CmdletBinding()]
Param(
    [string]$url
)   

    Test-MBAMWCFServiceState -serviceType user -uri $url -id FBP-MBAM-0008 -moduleId TC-MBAM-0007
}

function Test-MbamStatusReportSvcRunning
{
<#
.SYNOPSIS
    Tests if the MBAM status report web service is running.
.DESCRIPTION
    Tests if the MBAM status report web service is running. As we need credentials to connect to the web service we only request the service and check the answer for a 401 forbidden.
    With a 401 we asume the service is up and running.
.PARAMETER url
    URL of the MBAM server including http:// or https://
.EXAMPLE
    PS C:\> Test-MbamStatusReportSvcRunning -url http://mbam.services.corp.fbpro

    ID       : FBP-MBAM-0009
    moduleID : TC-MBAM-0008
    Task     : Webservice StatusReportingService.svc running
    Status   : Running
    Passed   : Passed
.NOTES
    ID        FBP-MBAM-0009
    moduleID  TC-MBAM-0008
#>
[CmdletBinding()]
Param(
    [string]$url
)   

    Test-MBAMWCFServiceState -serviceType report -uri $url -id FBP-MBAM-0009 -moduleId TC-MBAM-0008
}

function Test-MbamCoreSvcRunning
{
<#
.SYNOPSIS
    Tests if the MBAM core web service is running.
.DESCRIPTION
    Tests if the MBAM cire web service is running. As we need credentials to connect to the web service we only request the service and check the answer for a 401 forbidden.
    With a 401 we asume the service is up and running.
.PARAMETER url
    URL of the MBAM server including http:// or https://
.EXAMPLE
    PS C:\> Test-MbamStatusReportSvcRunning -url http://mbam.services.corp.fbpro

    ID       : FBP-MBAM-0009
    moduleID : TC-MBAM-0008
    Task     : Webservice StatusReportingService.svc running
    Status   : Running
    Passed   : Passed
.NOTES
    ID        FBP-MBAM-0010
    moduleID  TC-MBAM-0009
#>
[CmdletBinding()]
Param(
    [string]$url
)   

    Test-MbamWCFServiceState -serviceType report -uri $url -id FBP-MBAM-0010 -moduleId TC-MBAM-0009
}

function Test-MbamHelpDeskSslOnly
{
<#
.Synopsis
    Checks, if the MBAM webpages for HelpDesk is only reachable on https.
.DESCRIPTION
    Checks, if the MBAM webpages for HelpDesk is only reachable on https.
.NOTES
    ID        FBP-MBAM-0011
    moduleID  TC-MBAM-0011
#>
[CmdletBinding()]
Param()

    $server = Get-MBAMHostname
    $helpdesk = Get-MBAMWebApplication -AdministrationPortal | Select-Object -ExpandProperty VirtualDirectory  

    $obj = [TapResult]::New("FBP-MBAM-0011", "TC-MBAM-0011", "HelpDesk page $server$helpdesk is only reachable over SSL connection")

    $https = Test-MBAMHelpDeskPage -https
    $http = Test-MBAMHelpDeskPage 
    
    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[FBP-MBAM-0011]" + [System.Environment]::NewLine
    $messageBag += "Module ID: [TC-MBAM-0011]"  

    if (($https.Passed -eq 1) -and ($http.Passed -eq 2))
    {
        $obj.Status = "Only reachable over https"
        $obj.Passed = 1
    }
    elseif (($https.Passed -eq 1) -and ($http.Passed -eq 1))
    {
        $obj.Status = "Reachable over https and http"
        $obj.Passed = 3

        $msg = "The MBAM HelpDesk site is also reachable over http"+[System.Environment]::NewLine
        $msg += $messageBag
        Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 4 -EntryType Warning -Category 0 
    }
    elseif (($https.Passed -eq 2) -and ($http.Passed -eq 1))
    {
        $obj.Status = "Only reachable over http"
        $obj.Passed = 2

        
        $msg = "The MBAM HelpDesk site is only reachable over http"+[System.Environment]::NewLine
        $msg += $messageBag
        Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 5 -EntryType Error -Category 0 
    }
    else
    {
        $obj.Status = "Not reachable at all"
        $obj.Passed = 4
       
        $msg = "The MBAM HelpDesk site is not reachable"+[System.Environment]::NewLine
        $msg += $messageBag
        Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 6 -EntryType Error -Category 0 
    }
        
    Write-Output $obj
}

function Test-MbamSelfServiceSslOnly
{
<#
.Synopsis
    Checks, if the MBAM webpage for SelfService is only reachable on https.
.DESCRIPTION
    Checks, if the MBAM webpage for SelfService is only reachable on https.
.NOTES
    ID        FBP-MBAM-0012
    moduleID  TC-MBAM-0012
#>
[CmdletBinding()]
Param()

    $server = Get-MBAMHostname
    $selfservice = Get-MBAMWebApplication -SelfServicePortal | Select-Object -ExpandProperty VirtualDirectory  

    $obj = [TapResult]::New("FBP-MBAM-0012", "TC-MBAM-0012", "SelfService page $server$selfservice is only reachable over SSL connection")

    $https = Test-MBAMSelfServicePage -https
    $http = Test-MBAMSelfServicePage
        
    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[FBP-MBAM-0012]" + [System.Environment]::NewLine
    $messageBag += "Module ID: [TC-MBAM-0012]"  

    if (($https.Passed -eq 1) -and ($http.Passed -eq 2))
    {
        $obj.Status = "Only reachable over https"
        $obj.Passed = 1
    }
    elseif (($https.Passed -eq 1) -and ($http.Passed -eq 1))
    {
        $obj.Status = "Reachable over https and http"
        $obj.Passed = 3

        $msg = "The MBAM SelfService site is also reachable over http"+[System.Environment]::NewLine
        $msg += $messageBag
        Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 7 -EntryType Warning -Category 0 
    }
    elseif (($https.Passed -eq 2) -and ($http.Passed -eq 1))
    {
        $obj.Status = "Only reachable over http"
        $obj.Passed = 2
       
        $msg = "The MBAM SelfService site is only reachable over http"+[System.Environment]::NewLine
        $msg += $messageBag
        Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 8 -EntryType Error -Category 0 
    }
    else
    {
        $obj.Status = "Not reachable at all"
        $obj.Passed = 4

        $msg = "The MBAM SelfService site is not reachable"+[System.Environment]::NewLine
        $msg += $messageBag
        Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 9 -EntryType Error -Category 0 
    }
        
    Write-Output $obj
}

function Test-MbamSQLSrvConnection
{
[CmdletBinding()]
Param(
    # IP-address or DNS of destination
    [Parameter(Mandatory=$true)]
    [string]$destination,

    [Parameter(Mandatory=$true)]
    [String]$Id,

    [String]$moduleId
)

    $obj = [TapResult]::New($Id, $moduleId, "SQL Server $destination is reachable")
        
    try 
    {
            $result = Test-Connection $destination -ErrorAction SilentlyContinue

            if ($null -ne $result)
            {
                $obj.Status = "Reachable" 
                $obj.Passed = 1
            }
            else
            {
                $obj.Status = "Not reachable"
                $obj.Passed = 2
            }
        }
    catch
    {
        $obj.Status = "Error"
        $obj.Passed = 4   
        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }

    Write-Output $obj
}

function Test-MbamComplianceDbSrvConnection                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     
{  
<#
.Synopsis
    Checks, if the SQL Server of the compliance database is reachable.
.DESCRIPTION
    Checks, if the SQL Server of the compliance database is reachable. Reachable means that the SQL server is reachable on the network, e.g. by ping.
.NOTES
    ID        FBP-MBAM-0013
    moduleID  TC-MBAM-0013
#>
[CmdletBinding()]
Param()
    
    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[FBP-MBAM-0013]" + [System.Environment]::NewLine
    $messageBag += "Module ID: [TC-MBAM-0013]"  

    try 
    {
        $connectionString = Get-MBAMWebApplication -AdministrationPortal -ErrorAction Stop | Select-Object -ExpandProperty ComplianceAndAuditDBConnectionString

        if($connectionString.Contains('\'))
        {
            # named sql instance
            $destination = $connectionString.Substring(12, $connectionString.LastIndexOf('\')-12)
        }
        else
        {
            # standard sql instance
            $destination = $connectionString.Substring(12, $connectionString.IndexOf(';')-12)
        }

        $obj = Test-MbamSQLSrvConnection -Id "FBP-MBAM-0013" -moduleId "TC-MBAM-0013" $destination -ErrorAction SilentlyContinue
        $obj.Task = "SQL Server of Compliance and Audit database $destination is reachable"

        if ($obj.Passed -eq 2)
        {
            $msg = "The SQL Server of the MBAM compliance and audit database could not be reach"+[System.Environment]::NewLine
            $msg += $messageBag
            Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 10 -EntryType Error -Category 0 
        }
    }
    catch
    {
        $obj = [TapResult]::New("FBP-MBAM-0013", "TC-MBAM-0013", "SQL Server of MBAM Compliance and Audit database is reachable")
        $obj. Status = "An error occured"
        $obj.Passed = 4

        # log error into log file and event log
        $e = $_.Exception.toString()
        $e += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $e -Level Error

        $msg = "An error occured reaching the SQL Server of the MBAM compliance and audit database"+[System.Environment]::NewLine
        $msg += $messageBag+[System.Environment]::NewLine
        $msg += $e
        Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 11 -EntryType Error -Category 0 
    }

    Write-Output $obj
}

function Test-MbamRecoveryDbSrvConnection
{
<#
.Synopsis
    Checks, if the SQL Server of the recovery database is reachable.
.DESCRIPTION
    Checks, if the SQL Server of the recovery database is reachable. Reachable means that the SQL server is reachable on the network, e.g. by ping.
.NOTES
    ID        FBP-MBAM-0014
    moduleID  TC-MBAM-0014
#>
[CmdletBinding()]
Param()

    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[FBP-MBAM-0014]" + [System.Environment]::NewLine
    $messageBag += "Module ID: [TC-MBAM-0014]"  

    try
    {

        $connectionString = Get-MBAMWebApplication -AdministrationPortal -ErrorAction Stop| Select-Object -ExpandProperty RecoveryDBConnectionString

        if($connectionString.Contains('\'))
        {
            # named sql instance
            $destination = $connectionString.Substring(12, $connectionString.LastIndexOf('\')-12)
        }
        else
        {
            # standard sql instance
            $destination = $connectionString.Substring(12, $connectionString.IndexOf(';')-12)
        }

        $obj = Test-MbamSQLSrvConnection -Id "FBP-MBAM-0014" -moduleId "TC-MBAM-0014" $destination -ErrorAction SilentlyContinue
        $obj.Task = "SQL Server of Recovery database $destination is reachable"

        if ($obj.Passed -eq 2)
        {
            $msg = "The SQL Server of the MBAM Recovery database could not be reach"+[System.Environment]::NewLine
            $msg += $messageBag
            Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 12 -EntryType Error -Category 0 
        }
    }
    catch
    {
        $obj = [TapResult]::New("FBP-MBAM-0014", "TC-MBAM-0014", "SQL Server of MBAM Recovery database is reachable")
        $obj. Status = "An error occured"
        $obj.Passed = 4

        # log error into log file and event log
        $e = $_.Exception.toString()
        $e += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $e -Level Error

        $msg = "An error occured reaching the SQL Server of the MBAM Recovery database"+[System.Environment]::NewLine
        $msg += $messageBag+[System.Environment]::NewLine
        $msg += $e
        Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 13 -EntryType Error -Category 0 
    }

    Write-Output $obj
}

function Test-MbamHelpDeskPage
{
<#
.Synopsis
    Checks, if the HelpDesk page is reachable
.DESCRIPTION
    Checks, if the HelpDesk page is reachable. 
.NOTES
    ID        FBP-MBAM-0015
    moduleID  TC-MBAM-0015
#>
[CmdletBinding()]
Param(
    # Opend web site with TLS 
    [switch]$https
)    
    $obj = [TapResult]::New("FBP-MBAM-0015", "TC-MBAM-0015", "HelpDesk page $server$helpdesk is reachable")
           
    try
    {
        try
        {
            $server = Get-MBAMHostname
           
            $helpdesk = Get-MBAMWebApplication -AdministrationPortal -ErrorAction Stop | Select-Object -ExpandProperty VirtualDirectory 
  
            $protocol = @{$true = "https://"; $false = "http://"}[$https -eq $true] 
        }
        catch
        {
            $errorMessage = "Could not retrieve hostname or virtual directory of MBAM HelpDesk page"
            $errorMessage += $_.Exception
            Write-LogFile -Path $LogPath -name $LogName -message $errorMessage -Level Error
        }

        # webrequest should fail because we did not pass credentials, but if we Get a 401, the page is running
        Invoke-WebRequest -URI ($protocol+$server+$helpdesk)
    }
            
    # catch expected 401 error
    catch [System.Net.WebException]
    {
        # let's check if we are not authorized, which in this case is good because the page seems to be running
        if ($_.ErrorDetails.Message -like "*401.2*")
        {
            $obj.Status = "Reachable"
            $obj.Passed = 1
        }
        else
        {
            $obj.Status = "Not reachable"
            $obj.Passed = 2
        }      
    }
    
    # catch unexpected errors
    catch
    {
        $obj.Status = "Not reachable"
        $obj.Passed = 4
        Write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error
    }

    Write-Output $obj
    
}

function Test-MbamSelfServicePage
{
<#
.Synopsis
    Checks, if the HelpDesk page is reachable
.DESCRIPTION
    Checks, if the HelpDesk page is reachable. At this time it only checks https connections. 
.NOTES
    ID        FBP-MBAM-0016
    moduleID  TC-MBAM-0016
#>
[CmdletBinding()]
Param(
    # Check with SSL connection
    [switch]$https
)
    
    $obj = [TapResult]::New("FBP-MBAM-0016", "TC-MBAM-0016", "SelfService page $server$selfservice is reachable")
    
    try
    {
        try
        {
            $server = Get-MBAMHostname

            $selfservice = Get-MBAMWebApplication -SelfServicePortal | Select-Object -ExpandProperty VirtualDirectory 
 
            $protocol = @{$true = "https://"; $false = "http://"}[$https -eq $true] 
        }
        catch
        {
            $errorMessage = "Could not retrieve hostname or virtual directory of MBAM SelfService page"
            $errorMessage += $_.Exception
            Write-LogFile -Path $LogPath -name $LogName -message $errorMessage -Level Error
        }

        # webrequest should fail because we did not pass credentials, but if we Get a 401, the page is running
        Invoke-WebRequest -URI ($protocol+$server+$selfservice)
    }

    # catch expected 401 error
    catch [System.Net.WebException]
    {
        # let's check if we are not authorized, which in this case is good because the page seems to be running
        if ($_.ErrorDetails.Message -like "*401.2*")
        {
            $obj.Status = "Reachable"
            $obj.Passed = 1
        }
        else
        {
            $obj.Status = "Not reachable"
            $obj.Passed = 2
        }
    }
    catch
    {  
        $obj.Status = "Not reachable"
        $obj.Passed = 4
        Write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error
    }

    Write-Output $obj
}

function Test-MbamSrvFeatureInstalled
{
<#
.Synopsis
    Checks, if the MBAM Server features are installed.
.DESCRIPTION
    Checks, if the MBAM Server features are installed.
.NOTES
    ID        FBP-MBAM-0029
    moduleID  TC-MBAM-0061
#>
[CmdletBinding()]
Param()
    
    $obj = [TapResult]::New("FBP-MBAM-0029", "TC-MBAM-0061", "The MBAM server features are installed")

    $registryPath = "HKLM:\SOFTWARE\Microsoft\MBAM Server\Install\ServerFeatures"
    $registryKey = "Installed"
    $regValue = 1

    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[FBP-MBAM-0029]" + [System.Environment]::NewLine
    $messageBag += "Module ID: [TC-MBAM-0061]"  

    try 
    {
        Write-Verbose "[FBP-MBAM-0029]:Checking registry entry of MBAM Server installation"
        $regEntry = Get-ItemProperty $registryPath -ErrorAction Stop | Select-Object -ExpandProperty $registryKey 

        if ($regEntry -eq $regValue) 
        {
            $obj.Status = "Features installed"
            $obj.Passed = 1
        }
        else
        {
            $obj.Status = "Features not installed (Registry mismatch)"
            $obj.Passed = 2

            $msg = "MBAM Features not installed (Registry mismatch)"+[System.Environment]::NewLine
            $msg += $messageBag+[System.Environment]::NewLine
            Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 15 -EntryType Error -Category 0
        }   
    }

    catch
    {
        $obj.Status = "Features not installed (Registry key not found)"
        $obj.Passed = 4

        # log error into log file and event log
        $e = $_.Exception.toString()
        $e += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $e -Level Error

        $msg = "MBAM Features not installed (Registry key not found)"+[System.Environment]::NewLine
        $msg += $messageBag+[System.Environment]::NewLine
        $msg += $e
        Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 14 -EntryType Error -Category 0
    }

    Write-Output $obj
}

function Test-MbamHelpDeskPortalVersion
{
<#
.Synopsis
    Checks,if the version of the MBAM Adminstration Portal is correct.
.DESCRIPTION
    Checks,if the version of the MBAM Adminstration Portal is correct.
.PARAMETER version
    The expected version number of the HelpDesk portal
.NOTES
    ID        FBP-MBAM-0030
    moduleID  TC-MBAM-0051
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string] $version
)
    
    $obj = [TapResult]::New("FBP-MBAM-0030", "TC-MBAM-0051", "The MBAM Server HelpDesk(Administration) Portal version is correct")

    $registryPath = "HKLM:\SOFTWARE\Microsoft\MBAM Server\Version\"
    $registryKey = "AdministrationPortal"

    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[FBP-MBAM-0030]" + [System.Environment]::NewLine
    $messageBag += "Module ID: [TC-MBAM-0051]"  

    try 
    {
        $regEntry = Get-ItemProperty $registryPath -ErrorAction Stop | Select-Object -ExpandProperty $registryKey 

        if ($regEntry -eq $version)
        {
            $obj.Status = "Version correct, installed version is $regEntry"
            $obj.Passed = 1
        }
        else
        {
            $obj.Status = "Version not correct, installed is $regEntry"
            $obj.Passed = 3

            $msg = "The MBAM Server HelpDesk(Administration) Portal version is not correct."+[System.Environment]::NewLine
            $msg += "Expected version $version, found version $regEntry."+[System.Environment]::NewLine
            $msg += $messageBag
            Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 17 -EntryType Warning -Category 0
        }      
    }
    catch
    {
        $obj.Status = "Not installed"
        $obj.Passed = 2

        # log error into log file and event log
        $e = $_.Exception.toString()
        $e += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $e -Level Error

        $msg = "The MBAM Server HelpDesk(Administration) Portal is not installed"+[System.Environment]::NewLine
        $msg += $messageBag+[System.Environment]::NewLine
        $msg += $e
        Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 16 -EntryType Error -Category 0
    }

    Write-Output $obj
}

function Test-MbamSelfSvcPortalVersion
{
<#
.Synopsis
    Checks,if the version of the MBAM SelfService Portal is correct.
.DESCRIPTION
    Checks,if the version of the MBAM SelfService Portal is correct. Also checks, if the SelfService is expected to be active.
.PARAMETER version
    The expected version of the SelfService portal
.PARAMETER enabled
    Switch to indicated, if the SelfService portal is expected to be active
.NOTES
    ID        FBP-MBAM-0031
    moduleID  TC-MBAM-0052
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string] $version,

    [switch]$enabled
)
    
    $obj = [TapResult]::New("FBP-MBAM-0031", "TC-MBAM-0052", "The MBAM server SelfService Portal version is correct")

    $registryPath = "HKLM:\SOFTWARE\Microsoft\MBAM Server\Version\"
    $registryKey = "SelfServicePortal"

    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[FBP-MBAM-0031]" + [System.Environment]::NewLine
    $messageBag += "Module ID: [TC-MBAM-0052]"  

    try 
    {
        Write-Verbose "[FBP-MBAM-0031]:Getting registry entry"
        $regEntry = Get-ItemProperty $registryPath -ErrorAction Stop | Select-Object -ExpandProperty $registryKey 

        Write-Verbose "[FBP-MBAM-0031]:Compare versions"
        if (($regEntry -eq $version) -and $enabled)
        {
            $obj.Status = "Version correct, installed version is $regEntry"
            $obj.Passed = 1
        }
        elseif (($regEntry -eq $version) -and -not $enabled)
        {
            $obj.Status = "Version correct, but portal expected as disabled"
            $obj.Passed = 3

            $msg = "The MBAM SelfService portal version is correct, but feature is expected to be disabled."+[System.Environment]::NewLine
            $msg += $messageBag
            Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 18 -EntryType Warning -Category 0
        } 
        elseif (($regEntry -ne $version) -and $enabled)
        {
            $obj.Status = "Version not correct, installed version is $regEntry"
            $obj.Passed = 3

            $msg = "The MBAM SelfService portal version not correct, found version $regEntry, expected $version."+[System.Environment]::NewLine
            $msg += $messageBag
            Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 19 -EntryType Warning -Category 0
        }
        elseif (($regEntry -ne $version) -and -not $enabled)
        {
            $obj.Status = "Version not correct and SelfService unexpectedly active"
            $obj.Passed = 2

            $msg = "The MBAM SelfService portal unexpectedly active, also version mismatch, found $regEntry, should be $version."+[System.Environment]::NewLine
            $msg += $messageBag
            Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 20 -EntryType Error -Category 0
        }          
    }
    catch
    {
        # a registry entry is not found but Self-Service Portal should be enabled
        if($enabled)
        {
            # this leads to an error, because it is not installed
            $obj.Status = "Not installed"
            $obj.Passed = 4

            # log error
            $e = $_.Exception.toString()
            $e += "; " + $_.ScriptStackTrace.toString()
            write-LogFile -Path $LogPath -name $LogName -message $e -Level Error

            $msg = "The MBAM SelfService portal is not active, version check not possible."+[System.Environment]::NewLine
            $msg += $messageBag+[System.Environment]::NewLine
            $msg += $e
            Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 21 -EntryType Error -Category 0
        }
        # a registry entry is not found and the Self-Service Portal should be disabled
        else
        {
            # all good
            $obj.Status = "Not installed"
            $obj.Passed = 1
        }
    }

    Write-Output $obj
}

function Test-MbamSrvAgentSvcVersion
{
<#
.Synopsis
    Checks,if the version of the MBAM Server Agent Service is correct.
.DESCRIPTION
    Checks,if the version of the MBAM Server Agent Service is correct.
.PARAMETER
    The expected version number of the MBAM agent service
.NOTES
    ID        FBP-MBAM-0032
    moduleID  TC-MBAM-0053
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string] $version
)

    $obj = [TapResult]::New("FBP-MBAM-0032", "TC-MBAM-0053", "The MBAM Server Agent Service version is correct")

    $registryPath = "HKLM:\SOFTWARE\Microsoft\MBAM Server\Version\"
    $registryKey = "AgentServices"

    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[FBP-MBAM-0032]" + [System.Environment]::NewLine
    $messageBag += "Module ID: [TC-MBAM-0053]"  

    try 
    {
        Write-Verbose "[FBP-MBAM-0032]:Getting registry entry"
        $regEntry = Get-ItemProperty $registryPath -ErrorAction Stop | Select-Object -ExpandProperty $registryKey 

        Write-Verbose "[FBP-MBAM-0032]:Compare versions"
        if ($regEntry -eq $version)
        {
            $obj.Status = "Version correct, installed version is $regEntry"
            $obj.Passed = 1
        }
        else
        {
            $obj.Status("Version not correct, installed is $regEntry")
            $obj.Passed = 3

            $msg = "The MBAM Server Agent Service version is not correct, found version $regEntry, expected $version."+[System.Environment]::NewLine
            $msg += $messageBag
            Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 22 -EntryType Warning -Category 0
        }      
    }
    catch
    {
        $obj.Status = "Not installed"
        $obj.Passed = 4

        # log error
        $e = $_.Exception.toString()
        $e += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $e -Level Error

        $msg = "The MBAM Server Agent Service was not found."+[System.Environment]::NewLine
        $msg += $messageBag+[System.Environment]::NewLine
        $msg += $e
        Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 23 -EntryType Error -Category 0
    }

    Write-Output $obj

}

function Test-MbamSrvAgentSvcEnabled 
{
<#
.Synopsis
    Checks,if the MBAM Agent Service is activated in the registry.
.DESCRIPTION
    Checks,if the MBAM Agent Service is activated in the registry.
.NOTES
    ID        FBP-MBAM-0033
    moduleID  TC-MBAM-0054
#>
[cmdletBinding()]
Param()

    $obj = [TapResult]::New("FBP-MBAM-0033", "TC-MBAM-0054", "The MBAM Server Agent Service is enabled")

    $registryPath = "HKLM:\SOFTWARE\Microsoft\MBAM Server\Enabled\"
    $registryKey = "AgentServices"
    $registryValue = "1"

    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[FBP-MBAM-0033]" + [System.Environment]::NewLine
    $messageBag += "Module ID: [TC-MBAM-0054]" 

    try 
    { 
        $regEntry = Get-ItemProperty $registryPath -ErrorAction Stop | Select-Object -ExpandProperty $registryKey 

        if ($regEntry -eq $registryValue)
        {
            $obj.Status = "Enabled"
            $obj.Passed = 1
        }
        else
        {
            $obj.Status = "Disabled"
            $obj.Passed = 2

            $msg = "The MBAM Server Agent Service is disabled"+[System.Environment]::NewLine
            $msg += $messageBag
            Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 24 -EntryType Error -Category 0
        }      
    }
    catch
    {
        $obj.Status = "Not installed"
        $obj.Passed = 4

        # log error
        $e = "FBP-MBAM-0033: "+$_.Exception.toString()
        $e += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $e -Level Error

        $msg = "The MBAM Server Agent Service was not found"+[System.Environment]::NewLine
        $msg += $messageBag+[System.Environment]::NewLine
        $msg += $e
        Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 23 -EntryType Error -Category 0
    }

    Write-Output $obj
}

function Test-MbamAdminPortalEnabled 
{
<#
.Synopsis
   Checks,if the MBAM Adminstration Portal is activated in the registry.
.DESCRIPTION
   Checks,if the MBAM Adminstration Portal is activated in the registry.
.NOTES
    ID        FBP-MBAM-0034
    moduleID  TC-MBAM-0055
#>
[CmdletBinding()]
Param()

    $obj = [TapResult]::New("FBP-MBAM-0034", "TC-MBAM-0055", "The MBAM Server HelpDesk(Administration) Portal is enabled")

    $registryPath = "HKLM:\SOFTWARE\Microsoft\MBAM Server\Enabled\"
    $registryKey = "AdministrationPortal"
    $registryValue = "1"

    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[FBP-MBAM-0034]" + [System.Environment]::NewLine
    $messageBag += "Module ID: [TC-MBAM-0055]" 

    try 
    {
        $regEntry = Get-ItemProperty $registryPath -ErrorAction Stop | Select-Object -ExpandProperty $registryKey 

        if ($regEntry -eq $registryValue)
        {
            $obj.Status = "Enabled"
            $obj.Passed = 1
        }
        else
        {
            $obj.Status = "Disabled"
            $obj.Passed = 2

            $msg = "The MBAM HelpDesk(Administration) Portal is disabled"+[System.Environment]::NewLine
            $msg += $messageBag
            Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 26 -EntryType Error -Category 0
        } 
      
    }
    catch
    {
        $obj.Status = "Not installed"
        $obj.Passed = 4

        # log error
        $e = "FBP-MBAM-0034: "+$_.Exception.toString()
        $e += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $e -Level Error

        $msg = "The MBAM HelpDesk(administration) Portal was not found in the registry."+[System.Environment]::NewLine
        $msg += $messageBag+[System.Environment]::NewLine
        $msg += $e
        Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 25 -EntryType Error -Category 0
    }

    Write-Output $obj

}

function Test-MbamSelfSvcPortalEnabled 
{
<#
.Synopsis
   Checks,if the MBAM Self-Service Portal is enabled in the registry.
.DESCRIPTION
   Checks,if the MBAM Self-Service Portal is enabled in the registry. As the Self-Service Portal is optional for ongoing MBAM operation,
   the test will return false if the Self-Service Portal is enabled but not expected to be enabled. You can indicate the expected status with
   the enabled switch.
   Enabled true => Found Self-Service => true
   Enabled true => No Self-Service => false
   Enabled false => Found Self-Service => false
   Enabled false => No Self-Service => true
.PARAMETER enabled
   Switch to indicated the expected status of the SelfService Portal
.NOTES
    ID        FBP-MBAM-0035
    moduleID  TC-MBAM-0056
#>
[CmdletBinding()]
Param(
    [switch]$enabled
)

    $obj = [TapResult]::New("FBP-MBAM-0035", "TC-MBAM-0056", "The MBAM SelfService Portal is enabled") 

    $registryPath = "HKLM:\SOFTWARE\Microsoft\MBAM Server\Enabled\"
    $registryKey = "SelfServicePortal"
    $registryValue = "1"
    
    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[FBP-MBAM-0035]" + [System.Environment]::NewLine
    $messageBag += "Module ID: [TC-MBAM-0055]" 

    try 
    {
        Write-Verbose "[FBP-MBAM-0035]: Getting registry entry"
        $regEntry = Get-ItemProperty $registryPath -ErrorAction Stop | Select-Object -ExpandProperty $registryKey 

        Write-Verbose "[FBP-MBAM-0035]: Checking if SelfService is enabled"
        # SelfService Portal enabled and like it should
        if (($regEntry -eq $registryValue) -and $enabled)
        {
            $obj.Status = "Enabled"
            $obj.Passed = 1
        }
        # SelfService Portal enabled but should be disabled
        elseif (($regEntry -eq $registryValue) -and -not $enabled)
        {
            $obj.Status = "Enabled, but expected as disabled"
            $obj.Passed = 3

            $msg = "The MBAM SelfService Portal is enabled but expected as disabled"+[System.Environment]::NewLine
            $msg += $messageBag
            Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 29 -EntryType Warning -Cat
        }
        # SelfService not enabled but should be
        elseif (($regEntry -ne $registryValue) -and $enabled)
        {
            $obj.Status = "Disabled, but expected enabled"
            $obj.Passed = 3

            $msg = "The MBAM SelfService Portal is disabled"+[System.Environment]::NewLine
            $msg += $messageBag
            Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 28 -EntryType Warning -Category 0
        }
        # SelfService not enabled, test passed
        else
        {
            $obj.Status = "Disabled"
            $obj.Passed = 1
        }        
    }

    catch
    {
        # a registry entry is not found but Self-Service Portal should be enabled
        if($enabled)
        {
            $obj.Status = "Not enabled"
            $obj.Passed = 2

            # log error
            $e = "FBP-MBAM-0035: The SelfService Portal not found in the registry"+[System.Environment]::NewLine+$_.Exception.toString()
            $e += "; " + $_.ScriptStackTrace.toString()
            write-LogFile -Path $LogPath -name $LogName -message $e -Level Error

            $msg = "The MBAM SelfService Portal was not found in the registry."+[System.Environment]::NewLine
            $msg += $messageBag+[System.Environment]::NewLine
            $msg += $e
            Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 27 -EntryType Error -Category 0
        }

        # a registry entry is not found and the Self-Service Portal should not be enabled
        else
        {
            # test case is passed
            $obj.Status = "Not enabled"
            $obj.Passed = 1
        }
    }

    Write-Output $obj
}

function Test-MbamHelpDeskVirtualDir
{
<#
.Synopsis
    Checks, if the MBAM HelpDesk Virtual Directory is correct.
.DESCRIPTION
    Checks, if the MBAM HelpDesk Virtual Directory is correct.
.PARAMETER virtualDirectory
    The name of the virtual directory
.NOTES
    ID        FBP-MBAM-0036
    moduleID  TC-MBAM-0059
#>
[CmdletBinding()]
Param(
    [string]$virtualDirectory = "/HelpDesk"
)

    $obj = [TapResult]::New("FBP-MBAM-0036", "TC-MBAM-0059", "The MBAM HelpDesk Virtual Directory is correct")

    $registryPath = "HKLM:\SOFTWARE\Microsoft\MBAM Server\Web\"
    $registryKey = "HelpDeskVirtualDirectory"

    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[FBP-MBAM-0036]" + [System.Environment]::NewLine
    $messageBag += "Module ID: [TC-MBAM-0059]"

    try 
    {
        $regEntry = Get-ItemProperty $registryPath -ErrorAction Stop | Select-Object -ExpandProperty $registryKey 

        if ($regEntry -eq $virtualDirectory)
        {
            $obj.Status = "Directory name correct ($virtualDirectory)"
            $obj.Passed = 1
        }
        else
        {
            $obj.Status = "Directory name not correct, found $regEntry"
            $obj.Passed = 2

            $msg = "HelpDesk Virtual Directory name not correct, found $registryPath instead."+[System.Environment]::NewLine
            $msg += $messageBag+[System.Environment]::NewLine
            Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 31 -EntryType Error -Category 0
        }      
    }
    catch
    {
        $obj.Status = "Not found"
        $obj.Passed = 4

        # log error
        $e = "No entry for the HelpDesk Virtual Directory found in the registry"
        $e += $_.Exception.toString()
        $e += "; " + $_.ScriptStackTrace.toString()
        Write-LogFile -Path $LogPath -name $LogName -message $e -Level Error

        $msg = "No entry for the HelpDesk Virtual Directory found in the registry"+[System.Environment]::NewLine
        $msg += $messageBag+[System.Environment]::NewLine
        $msg += $e
        Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 30 -EntryType Error -Category 0
    }

    Write-Output $obj
}

function Test-MbamSelfSvcVirtualDir
{
<#
.Synopsis
    Checks, if the MBAM SelfService Portal Virtual Directory is correct.
.DESCRIPTION
    Checks, if the MBAM SelfService Portal Virtual Directory is correct.
.PARAMETER virtualDirectory
    The name of the virtual directory
.PARAMETER enabled
    Switch if the SelfService is expected to be enabled or not
.NOTES
    ID        FBP-MBAM-0037
    moduleID  TC-MBAM-0060
#>
[CmdletBinding()]
Param(
    [string]$virtualDirectory = "/SelfService",

    [switch]$enabled
)

    $obj = [TapResult]::New("FBP-MBAM-0037", "TC-MBAM-0060", "The MBAM SelfService Portal Virtual Directory is correct")

    $registryPath = "HKLM:\SOFTWARE\Microsoft\MBAM Server\Web\"
    $registryKey = "SelfServicePortalVirtualDirectory"

    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[FBP-MBAM-0037]" + [System.Environment]::NewLine
    $messageBag += "Module ID: [TC-MBAM-0060]"

    try 
    {
        $regEntry = Get-ItemProperty $registryPath -ErrorAction Stop | Select-Object -ExpandProperty $registryKey

        if (($regEntry -eq $virtualDirectory) -and $enabled)
        {
            $obj.Status = "Directory name correct ($virtualDirectory)"
            $obj.Passed = 1
        }
        elseif (($regEntry -eq $virtualDirectory) -and -not $enabled)
        {
            $obj.Status = "Directory name correct $regEntry, but feature expected as disabled"
            $obj.Passed = 3
        }
        elseif (($regEntry -ne $virtualDirectory) -and $enabled)
        {
            $obj.Status("Directory name not correct, found $regEntry, expected $virtualDirectory")
            $obj.Passed = 2
        } 
        else
        {
            $obj.Status("Directory name not correct, found $regEntry, expected $virtualDirectory. Feature also expected as disabled")
            $obj.Passed = 2
        }      
    }
    catch
    {
        $obj.Status = "Entry not found"
        $obj.Passed = 4

        # log error
        $e = "No entry for the Self-Service Portal Virtual Directory found"
        $e += $_.Exception.toString()
        $e += "; " + $_.ScriptStackTrace.toString()
        Write-LogFile -Path $LogPath -name $LogName -message $e -Level Error

        $msg = "No entry for the Self-Service Portal Virtual Directory found in the registry"+[System.Environment]::NewLine
        $msg += $messageBag+[System.Environment]::NewLine
        $msg += $e
        Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 32 -EntryType Error -Category 0
    }

    Write-Output $obj
}

function Test-MbamServerVersion 
{ 
<#
.Synopsis
   Checks, if MBAM-Server main version is correct
.DESCRIPTION
   Checks, if the main version number of the installed MBAM-Server is correct. Does not check version number of features like HelpDesk or SelfService.
   Use Test-MbamHelpDeskPortalVersion or Test-MbamSelfSvcPortalVersion instead. 
   Targets installation with version numbers greater 2.5
.PARAMETER version 
    The MBAM servers expected main version number 
.NOTES
    ID        FBP-MBAM-0038
    moduleID  TC-MBAM-0032
#>
[CmdletBinding()]  
Param(
    # Version number
    [Parameter(Mandatory=$true)]
    [String]$version
)
    
    $obj = [TapResult]::New("FBP-MBAM-0038", "TC-MBAM-0032", "The MBAM Server main version number is correct")

    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[FBP-MBAM-0038]" + [System.Environment]::NewLine
    $messageBag += "Module ID: [TC-MBAM-0032]"

    try 
    {
        $currentVersion = Get-Item 'HKLM:\SOFTWARE\Microsoft\MBAM Server' -ErrorAction Stop | Get-ItemProperty | Select-Object -ExpandProperty "Installed"
        
        if ($version -eq $currentVersion)
        {
            $obj.Status = "Version correct, installed version is $currentVersion"
            $obj.Passed = 1
        }
        else
        {
            $obj.Status = "Versions differ, installed version is $currentVersion"
            $obj.Passed = 3

            $msg = "MBAM main version differ from expected, installed version is $currentVersion"+[System.Environment]::NewLine
            $msg += $messageBag
            Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 33 -EntryType Warning -Category 0
        }
    }
    catch 
    {
        $obj.Status = "No MBAM-Server Version >= 2.5 found"
        $obj.Passed = 4
        Write-LogFile -Path $LogPath -name $LogName -Message "Could not retrieve MBAM version. No registry entry for MBAM version >= 2.5 found"  -Level Error

        $msg = "Could not retrieve MBAM version. No registry entry for MBAM version 2.5 SP1 or later found"+[System.Environment]::NewLine
        $msg += $messageBag
        Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 34 -EntryType Error -Category 0
    }

    Write-Output $obj
}

function Test-MbamCertificateThumbprint
{
<#
.Synopsis
   Checks, if the MBAM Server TLS certificate is correct
.DESCRIPTION
   Checks, if the main version number of the installed MBAM-Server is correct. Does not check version number of features like HelpDesk or SelfService.
   Use Test-MbamHelpDeskPortalVersion or Test-MbamSelfSvcPortalVersion instead. 
   Targets installation with version numbers greater 2.5
.PARAMETER thumbprint 
    The expected TLS thumbprint
.NOTES
    ID        FBP-MBAM-0039
    moduleID  TC-MBAM-0010
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$thumbprint
)

    $obj = [TapResult]::New("FBP-MBAM-0039", "TC-MBAM-0010", "The MBAM server TLS certificate thumbprint is correct")

    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[FBP-MBAM-0039]" + [System.Environment]::NewLine
    $messageBag += "Module ID: [TC-MBAM-0010]"
    
    Write-Verbose "[FBP-MBAM-0039]: Getting MBAM TLs certificate thumbprint"
    # get the actual thumbprint of MBAM
    $actualThumbprint = Get-MBAMWebApplication -AdministrationPortal | Select-Object -ExpandProperty CertificateThumbprint

    Write-Verbose "[FBP-MBAM-0039]: Comparing thumbprint to expected one"
    # do the thumbprints match?
    if($actualThumbprint -eq $thumbprint)
    {
        $obj.Status = "Thumbprint is correct"
        $obj.Passed = 1
    }
    else
    {
        $obj.Status = "Thumbprint is not correct"
        $obj.Passed = 2

        $msg = "The MBAM TLS certificate thumbprint is not correct, found $actualThumbprint"+[System.Environment]::NewLine
        $msg += $messageBag

        Write-LogFile -Path $LogPath -name $LogName -Message $msg  -Level Error
        Write-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Message $msg -EventId 35 -EntryType Error -Category 0
    }

    Write-Output $obj
}


#endregion


#region 1.2 MBAM client tests
# ---------------------------
#
# Section for tests targeting the MBAM backend service
#=====================================================

function Test-MbamOsDiskProtectionStatus
{
<#
.SYNOPSIS
    Checks the protection status of the operating system drive
.DESCRIPTION
    Checks the protection status of the operating system drive. Protection status is ok if drive is encrypted and 
    protection is on.
.EXAMPLE

.NOTES
    ID           FBP-MBAM-0017
    Module ID    TC-MBAM-0025
#>
[CmdletBinding()]
Param()

    $obj = [TapResult]::New("FBP-MBAM-0017", "TC-MBAM-0025", "The operating system drive is 100 % encrypted and protection is on")    
    
    try 
    {
        if (get-Module -Name BitLocker)
        {
            $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop

            if ($volume.ProtectionStatus -eq "On") 
            {
                $obj.Status = "Protected and encrypted"
                $obj.Passed = 1
            }
            elseif (($volume.ProtectionStatus -eq "Off") -and ($volume.VolumeStatus -eq "FullyEncrypted"))
            {
                $obj.Status = "Encrypted but protection is off"
                $obj.Passed = 2
            }
            else
            {
                $obj.Status = "Not protected"
                $obj.Passed = 2
            }
        }
        else
        {
            $volume = Get-CimInstance -namespace root\CIMv2\Security\MicrosoftVolumeEncryption -class Win32_EncryptableVolume -filter "DriveLetter = `"$env:SystemDrive`""

            if ($volume.ProtectionStatus -eq 1)
            {
                $obj.Status = "Protected and encrypted"
                $obj.Passed = 1
            }
            else
            {
                # protection status is 0 
                switch($volume.ConverstionStatus)
                {
                    1 { $obj.Status = "Encrypted but protection is off" # protection is suspended
                        $obj.Passed = 2
                        }
                    2 { $obj.Status = "Not protected (encryption in progress)" # protection is off because volume is not yet fully encrypted
                        $obj.Passed = 2
                        }
                    3 { $obj.Status = "Not protected (decryption in progress)" # protection is off because volume will be decrypted
                        $obj.Passed = 2
                        }
                    default {   $obj.Status = "Not protected (fully decrypted)" # protection is off
                                $obj.Passed = 2
                            }
                }
            }
        }
    }
    catch 
    {
        $obj.Status = "An error occurred, see logfile for more info."
        $obj.Passed = 4
        
        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        Write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }

    Write-Output $obj
}

function Test-MbamDriveProtectionStatus
{
<#
.SYNOPSIS 
   Checks the protection status of all local drives.
.DESCRIPTION
   Checks the protection status of all fixed and removable drives. Rom drives like CD oder DVD are not included. 
   Protection status is ok if drive is encrypted and protection is on.
.OUTPUTS
    One protection status per given mounting point entry
.EXAMPLE
    Test-MBAMDriveProtectionStatus
.NOTES
    ID  FBP-MBAM-0018
    Module ID   TC-MBAM-0026
#>    
[CmdletBinding()]
Param()
    
    try 
    {
        if (get-Module -Name BitLocker)
        {
            $mountPoints = Get-Volume | Where-Object {($_.DriveType -like "Fixed") -OR ($_.DriveType -like "Removable")} 
            $i = 1

            foreach($mountPoint in $mountPoints)
            {
                $obj = [TapResult]::New("FBP-MBAM-0018.$i", "TC-MBAM-0026.$i", "The "+$mountPoint.DriveType+" Drive "+$mountPoint.DriveLetter+" is encrypted and protection is on")

                $volume = Get-BitLockerVolume -MountPoint $mountPoint.DriveLetter 

                if (($volume.ProtectionStatus -eq "On") -and ($volume.VolumeStatus -eq "FullyEncrypted"))
                {
                    $obj.Status = "Encrypted and protection is on"
                    $obj.Passed = 1
                }
                elseif (($volume.ProtectionStatus -eq "Off") -and ($volume.VolumeStatus -eq "FullyEncrypted"))
                {
                    $obj.Status = "Encrypted but protection is off"
                    $obj.Passed = 2
                }
                else
                {
                    $obj.Status = "Not protected"
                    $obj.Passed = 2
                }

                $i++

                Write-Output $obj
            } 
        }
    }
    catch 
    { 
        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }
}

function Test-MbamGpo
{
<#
.SYNOPSIS 
   Checks if all registry settings are matching the expected GPO specification
.DESCRIPTION
    Checks if all registry settings are matching the expected GPO specification. The specifications are listed in an xml file.
.PARAMETER xmlFilePath
    The path to the xml file with all GPO settings
.NOTES
    ID  FBP-MBAM-0018
    Module ID   TC-MBAM-0027
#> 
[CmdletBinding()]
Param(
    # path to xml file with GPO settings
    [Parameter(Mandatory=$true)]
    [System.String]$xmlFilePath
)

    Try
    {
        [xml]$xml = Get-Content $xmlFilePath -ErrorAction Stop

        foreach($policy in $xml.GPO.Policy)
        {
            $obj = [TapResult]::New("FBP-MBAM-0019.$($policy.PolicyID)", "TC-MBAM-0027.$($policy.PolicyID)", "GPO: $($policy.PolicyName)")


            if($policy.PolicyState -eq 'enabled')
            {
                try 
                {
                    if (Get-MBAMGpoRuleState -PolicyKey $policy.PolicyKey -PolicyValue $policy.PolicyValue -path $policy.PolicyPath -ErrorAction Stop)
                    {
                        $obj.Status = "Policy correct and applied"
                        $obj.Passed = 1
                    }
                    else
                    {                   
                        $obj.Status = "Policy value not correct"
                        $obj.Passed = 3
                    }
                }
                catch
                {
                    $obj.Status = "Policy not applied"
                    $obj.Passed = 2
                }            
            }

            if($policy.PolicyState -eq 'disabled')
            {
                try 
                {
                    Get-MBAMGpoRuleState -PolicyKey $policy.PolicyKey -PolicyValue $policy.PolicyValue -path $policy.PolicyPath -ErrorAction Stop | Out-Null
                    
                    $obj.Status = "Policy falsely enabled"
                    $obj.Passed = 2

                    # log error
                    $mes = "MBAM Policy $($policy.PolicyKey) falsely enabled, please check settings."+[System.Environment]::NewLine
                    $msg += $_.Exception.toString()+[System.Environment]::NewLine
                    $msg += "; " + $_.ScriptStackTrace.toString()
                    write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error

                }
                catch
                {
                    $obj.Status = "Policy disabled as expected"
                    $obj.Passed = 1
                }            
            }

            Write-Output $obj
            $i++
        }
    }
    catch 
    {
        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }    
}

function Test-MbamClientSoftwareState
{
<#
.SYNOPSIS 
    Checks installation status of MDOP MBAM software.
.DESCRIPTION
    Checks installation status of MDOP MBAM software.
.NOTES
    ID  FBP-MBAM-0020
    Module ID   TC-MBAM-0028
#> 
[CmdletBinding()]
Param()

    $obj = [TapResult]::New("FBP-MBAM-0020", "TC-MBAM-0028", "Status of MDOP MBAM software package")

    try 
    {
        $MBAM = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object DisplayName -eq "MDOP MBAM"      
            
        if (!($null -eq $MBAM))
        {
            $obj.Status = "Installed"
            $obj.Passed = 1
        }
        else
        {
            $obj.Status = "MDOP MBAM Software not found"
            $obj.Passed = 2
        } 
    }
    catch
    {
        $obj.Status = "An error occurred, see logfile for more infos."
        $obj.Passed = 4

        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }

    Write-Output $obj
}

function Test-MbamClientAgentServiceState
{
<#
.Synopsis 
    Checks the MBAM client agent status 
.DESCRIPTION
    Checks the MBAM client agent status
.NOTES
    ID  FBP-MBAM-0021
    Module ID   TC-MBAM-0029
#>
[CmdletBinding()]
Param()
 
    $obj = [TapResult]::New("FBP-MBAM-0021", "TC-MBAM-0029", "Status of BitLocker Management Client-Service")
    
    try 
    {
        $agent = Get-Service -Name MBAMAgent -ErrorAction Stop

            
        if($agent.Status -eq "Running")
        {
            $obj.Status = $agent.Status.ToString()
            $obj.Passed = 1
        }
        else
        {
            $obj.Status = $agent.Status.ToString()
            $obj.Passed = 2
        } 
    }
    catch
    {
        $obj.Status = "Service not found"
        $obj.Passed = 4

        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }

    Write-Output $obj
}

function Test-MbamClientAgentVersion 
{
<#
.Synopsis
    Checks MBAM-Agent version of a client
.DESCRIPTION
    Checks the MBAM-Agent version of a client
.PARAMETER version
    The expected version of the MDOP MBAM package
.NOTES
    ID  FBP-MBAM-0022
    Module ID   TC-MBAM-0030
    
    WinRM has to be activated on the remote machine to get a version number of a remote client
#> 
[CmdletBinding()]
Param
(
    [Parameter(Mandatory=$true)]
    [Alias('ClientAgentVersion')]
    [string]$version  
)

    $obj = [TapResult]::New("FBP-MBAM-0022", "TC-MBAM-0030", "The MBAM-Agent version on client is up to date")

    $currentVersion = Get-MBAMClientAgentVersion

    if ($version -eq $currentVersion)
    {
        $obj.Status = "Version correct, installed version is $currentVersion"
        $obj.Passed = 1
    }
    elseif($currentVersion -eq "0")
    {
        $obj.Status = "No client agent found."
        $obj.Passed = 2  
    }
    else
    {
        $obj.Status = "Versions differ, installed version is $currentVersion"
        $obj.Passed = 3 
    }

    Write-Output $obj
}

function Test-MbamClient2ServerKeyReporting
{
<#
.Synopsis
    Checks if the client escrowed the key to the MBAM server.
.DESCRIPTION
    Checks if the client escrowed the key to the MBAM server within the defined frequency.
.NOTES
    ID  FBP-MBAM-0023
    Module ID   TC-MBAM-0031.1
#> 
[CmdletBinding()]
Param()

    $obj = [TapResult]::New("FBP-MBAM-0023", "TC-MBAM-0031.1", "Client escrowed key to MBAM server")

    try 
    {
        Write-Verbose "[FBP-MBAM-0023]:Get time of last escrowed key"
        $keyEscrowedTime = Get-WinEvent -FilterHashtable @{logname="microsoft-windows-MBAM/operational";ID=29} -MaxEvents 1 -ErrorAction Stop | Select-Object -ExpandProperty TimeCreated
    
        Write-Verbose "[FBP-MBAM-0023]:Get key report frequency"
        $reportFrequency = Get-Item 'HKLM:\SOFTWARE\Policies\Microsoft\FVE\MDOPBitLockerManagement' -ErrorAction Stop | Get-ItemProperty | Select-Object -ExpandProperty "clientWakeupFrequency"

        Write-Verbose "[FBP-MBAM-0023]:Get last system startup time"
        $lastStartup = Get-SystemStartupTime
        
        $time = (Get-Date).AddMinutes(-$reportFrequency)

        Write-Verbose "[FBP-MBAM-0023]:Check if time difference is valid"    
        if ($lastStartup -gt $time)
        {
            if($keyEscrowedTime -gt $time)
            {
                $obj.Status = "Key escrowed at $keyEscrowedTime"
                $obj.Passed = 1
            }
            else
            {
                $obj.Status = "Last system startup within report frequency, key not escrowed yet"
                $obj.Passed = 3
            }
        }
        else
        {
            if($keyEscrowedTime -gt $time)
            {
                $obj.Status = "Key escrowed at $keyEscrowedTime"
                $obj.Passed = 1
            }
            else
            {
                $obj.Status = "No key escrowed within regular frequency"
                $obj.Passed = 2
            }
        }
    }
    catch
    {
        $obj.Status = "An error occurred, see log file for more info."
        $obj.Passed = 4

        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }

    Write-Output $obj
}

function Test-MbamClient2ServerStatusReporting
{
<#
.Synopsis
    Checks if the client reported the status to the MBAM server.
.DESCRIPTION
    Checks if the client reported the status to the MBAM server within the defined frequency.
.NOTES
    ID  FBP-MBAM-0023
    Module ID   TC-MBAM-0031.2
#> 
[CmdletBinding()]
Param()

    $obj = [TapResult]::New("FBP-MBAM-0023", "TC-MBAM-0031.2", "Client reported status to MBAM server")

    try 
    {
        Write-Verbose "[FBP-MBAM-0023]:Get last report send time"
        $lastStatusReportTime = Get-WinEvent -FilterHashtable @{logname="microsoft-windows-MBAM/operational";ID=3} -MaxEvents 1 -ErrorAction Stop | Select-Object -ExpandProperty TimeCreated
    
        Write-Verbose "[FBP-MBAM-0023]:Get status report frequency"
        $statusReportingFrequency = Get-item 'HKLM:\SOFTWARE\Policies\Microsoft\FVE\MDOPBitLockerManagement' -ErrorAction Stop | Get-ItemProperty | Select-Object -ExpandProperty "StatusReportingFrequency"
        
        Write-Verbose "[FBP-MBAM-0023]:Get system up time (active)"
        $systemUpTime = (Measure-SystemUpTime).TotalMinutes
        
        # current time minus the status report frequency => period of time in which status should be reported
        $StatusReportDeadline = (Get-Date).AddMinutes(-$statusReportingFrequency)

        Write-Verbose "[FBP-MBAM-0023]: Check if status was reported within valid frequency"  
        
        if ($systemUpTime -lt $StatusReportDeadline)
        {
            # if system up time is lower than status report frequency
            # and status was reported
            if($statusReportedTime -gt $StatusReportDeadline)
            {
                # all good
                $obj.Status = "Status reported at $statusReportedTime"
                $obj.Passed = 1
            }
            # status was not reported, but system up time minutes lower than report frequency minutes
            else
            {
                $obj.Status = "System up time within report frequency, status not reported yet"
                $obj.Passed = 3
            }
        } 
        else
        {
            # if system up time is greater than status report frequency
            # and status was reported
            if($statusReportedTime -gt $StatusReportDeadline)
            {
                $obj.Status = "Status reported at $statusReportedTime"
                $obj.Passed = 1
            }
            # status was not reported and system up time exceeds report frequency
            else
            {
                $obj.Status = "No status reported within regular frequency"
                $obj.Passed = 2
            }
        }
    }
    catch
    {
        $obj.Status = "An error occurred, see log file for more info."
        $obj.Passed = 4

        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }

    Write-Output $obj
}

function Test-MbamTPMStatus
{
<#
.Synopsis 
    Checks the TPM status. 
.DESCRIPTION
    Checks if the TPM chip is present and activated.
.NOTES
    ID  FBP-MBAM-0024
    Module ID   TC-MBAM-0036
#>
[CmdletBinding()]
Param()

    $obj = [TapResult]::New("FBP-MBAM-0024", "TC-MBAM-0036", "Status of TPM chip")

    try
    {
        $tpm = Get-TpmObject

        if ($tpm.IsActivated_InitialValue -and $tpm.IsEnabled_InitialValue)
        {
            $obj.Status = "TPM present and ready"
            $obj.Passed = 1
        }
        elseif ($tpm.IsActivated_InitialValue -and !$tpm.IsEnabled_InitialValue)
        {
            $obj.Status = "TPM present but not ready"
            $obj.Passed = 3
        }
        else
        {
            $obj.Status = "TPM not present"
            $obj.Passed = 2
        }
    }
    catch
    {
        $obj.Status = "An error occurred, see logfile for more infos."
        $obj.Passed = 4

        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }

    Write-Output $obj
}

function Test-MbamTpmOwnerShip
{
<#
.Synopsis
    Checks the ownership of the TPM chip.
.DESCRIPTION
    Checks the ownership of the TPM chip.
.NOTES
    ID  FBP-MBAM-0025
    Module ID   TC-MBAM-0037
#>
[CmdletBinding()]
Param()

    $obj = [TapResult]::New("FBP-MBAM-0025", "TC-MBAM-0037", "TPM chip is owned by operating system")

    $tpm = Get-TpmObject

    if($null -ne $tpm)
    {
        if($tpm.IsOwned_InitialValue)
        {
            $obj.Status = "TPM is owned"
            $obj.Passed = 1
        }
        else
        {
            $obj.Status = "TPM not owned"
            $obj.Passed = 2
        }
    }
    else
    {
        $obj.Status = "TPM not found"
        $obj.Passed = 4
        
        # log error
        $msg = "No TPM chip found."
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }

    Write-Output $obj
}

function Test-MbamTpmVersion
{
<#
.Synopsis
    Checks the ownership of the TPM chip.
.DESCRIPTION
    Checks the ownership of the TPM chip.
.PARAMETER version
    Minimu version of TPM chip
.NOTES
    ID  FBP-MBAM-0026
    Module ID   TC-MBAM-0041
#>
[CmdletBinding()]
Param(
    [single]$version = 1.2
)

    $obj = [TapResult]::New("FBP-MBAM-0026", "TC-MBAM-0041", "TPM chip version is at least $version")

    $tpm = Get-TpmObject

    if($null -ne $tpm)
    {
        $tpmversion = [single]$tpm.SpecVersion.Substring(0,$tpm.SpecVersion.IndexOf(','))
        
        if($tpmversion -ge $version)
        {
            $obj.Status = "TPM version is $tpmversion"
            $obj.Passed = 1
        }
        else
        {
            $obj.Status = "TPM version is $tpmversion"
            $obj.Passed = 2
        }  
    }
    else
    {
        $obj.Status = "TPM not found"
        $obj.Passed = 4

        # log error
        $msg = "No TPM chip found."
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }

    Write-Output $obj
}

function Test-BitlockerDriverVersion
{
<#
.Synopsis 
    Checks, if the BitLocker driver version is up to date.
.DESCRIPTION
    Checks, if the BitLocker driver version is up to date. At the moment this test only works for Windows 7 SP1 , 8.1 and 10.
.NOTES
    ID  FBP-MBAM-0027
    Module ID   TC-MBAM-0049
#>
[CmdletBinding()]
Param()

    try
    {       
        $file = Get-Item C:\Windows\System32\drivers\fvevol.sys 
        $fileVersion = -join($file.VersionInfo.ProductMajorPart,$file.VersionInfo.ProductMinorPart,$file.VersionInfo.ProductBuildPart,$file.VersionInfo.ProductPrivatePart)
        $osVersion = Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Version
    }
    catch
    {
        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }

    switch ($osVersion)
    {
        "6.1.7601" { $expectedFileVersion = "61760123003"; break } # Windows 7
        "6.3.9600" { $expectedFileVersion = "63960017031"; break } 
        "10.0.14393" { $expectedFileversion = "100143930"; break } # Windows 10 
        "10.0.15063" { $expectedFileVersion = "10015063502"; break } # Windows 10 Creators Update 1703
        "10.0.16299" { $expectedFileVersion = "10016299371"; break } # Windows 10 fall update 1709
        "10.0.17134" { $expectedFileVersion = "10017134441"; break } # Windows 10 spring update 1803
        default { $expectedFileVersion = "0"; break }
    }

    # Create the test result object
    $obj = [TapResult]::New("FBP-MBAM-0027", "TC-MBAM-0049", "The BitLocker driver version is correct.")


    # Driver version matches
    if ($expectedFileVersion -eq $fileVersion)
    {
        $obj.Status = "Driver is up to date."
        $obj.Passed = 1
    }

    # Operating system not in the list
    elseif ($expectedFileVersion -eq 0)
    {
        $obj.Status = "Operating system not in list." 
        $obj.Passed = 2
    } 

    # A newer driver version is available
    elseif ($expectedFileVersion -gt $fileVersion)
    {
        $obj.Status = "Driver version is older than expected."
        $obj.Passed = 3
    }

    # A driver version with a higher version number is already installed 
    elseif ($expectedFileVersion -lt $fileVersion)
    {
        $obj.Status = "Driver version is higher than expected."
        $obj.Passed = 3
    }

    Write-Output $obj
}

function Test-TPMFirmwareVul 
{
<#
.Synopsis 
    Checks, if the TPM is vulnerable for security advisory ADV170012
.DESCRIPTION
    Checks, if the TPM is vulnerable for security advisory ADV170012. See https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV170012 for 
    further information.
.LINK https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV170012
.NOTES
    ID  FBP-MBAM-0028
    Module ID   TC-MBAM-0050
#>

#TODO: testen, ob entsprechendes Update installiert ist
[CmdletBinding()]
Param()

    try
    {
        # Get first event which indicates vulnerability
        $vulEvent = Get-EventLog -LogName System | Where-Object {($_.eventID -eq 1794) -and ($_.Source -eq "TPM-WMI")} | Select-Object -First 1  -ErrorAction Stop  
    }
    catch
    {
        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }

    # Create the test result object
    $obj = [TapResult]::New("FBP-MBAM-0028", "TC-MBAM-0050", "ADV170012 | Vulnerability in TPM could allow Security Feature Bypass.")

    # No event found
    if ($null -eq $vulEvent)
    {
        $obj.Status = "TPM not vulnerable"
        $obj.Passed = 1
    }
    # Event found, we have to check if it is an old entry or if it was logged after the last system boot up time
    else
    {
        $lastboot = Get-CimInstance -ClassName win32_operatingsystem | Select-Object lastbootuptime

        if ($lastboot.lastbootuptime -lt $vulEvent.TimeGenerated)
        {
            $obj.Status = "TPM vulnerable, found event 1794"
            $obj.Passed = 2
        }
        else
        {
            $obj.Status = "TPM not vulnerable"
            $obj.Passed = 1
        }
    }

    Write-Output $obj
}

#endregion

#endregion


#region 2 Helper functions
# ------------------
#
# Section for all helper functions 
#
###############################################################



#region 2.1 Client specific helpers
# ---------------------------
#
# Section for helper functions targeting a client computer
#=========================================================

function Get-MbamStatusReportFrequency
{
[CmdletBinding()]
Param()

    try
    {
       Write-Output (Get-Item "HKLM:\Software\Policies\Microsoft\FVE\MDOPBitLockerManagement" -ErrorAction Stop | Get-ItemProperty | Select-Object -ExpandProperty StatusReportingFrequency)
    }
    catch
    {
        throw "Policy not found"
        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        Write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error     
    }  
}

function Get-MbamKeyReportFrequency
{
[CmdletBinding()]
Param()

    try
    {
       Write-Output (Get-Item "HKLM:\Software\Policies\Microsoft\FVE\MDOPBitLockerManagement" -ErrorAction Stop | Get-ItemProperty | Select-Object -ExpandProperty ClientWakeupFrequency)
    }
    catch
    {
        throw "Policy not found"
        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        Write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error     
    } 
}

function Get-MbamStatusWebServiceUrl
{
[CmdletBinding()]
Param()

    try
    {
       Write-Output (Get-Item "HKLM:\Software\Policies\Microsoft\FVE\MDOPBitLockerManagement" -ErrorAction Stop | Get-ItemProperty | Select-Object -ExpandProperty StatusReportingServiceEndpoint)
    }
    catch
    {
        throw "Policy not found"
        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        Write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error     
    } 
}

function Get-MbamKeyWebServiceUrl
{
[CmdletBinding()]
Param()

    try
    {
       Write-Output (Get-Item "HKLM:\Software\Policies\Microsoft\FVE\MDOPBitLockerManagement" -ErrorAction Stop | Get-ItemProperty | Select-Object -ExpandProperty KeyRecoveryServiceEndPoint)
    }
    catch
    {
        throw "Policy not found"
        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        Write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error     
    } 
}

function Get-MbamClientAgentVersion 
{
<#
.Synopsis
   Gets the MBAM-Agent version of a client.
.DESCRIPTION
   Gets the MBAM-Agent version of a client.
.NOTES
   WinRM has to be activated on the remote machine to Get a version number of a remote client
#>
[CmdletBinding()]
Param()

    try
    {
        Get-Item 'HKLM:SOFTWARE\Microsoft\MBAM' -ErrorAction Stop | Get-ItemProperty | Select-Object -ExpandProperty "AgentVersion"
    }
    catch
    {
        Write-Output "0"

        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }
}

function Get-MbamOSDiskProtectionStatus
{  
<#
.Synopsis
   Gets the protection status of the operating system hard disk drive
.DESCRIPTION
   Gets the protection status of the operating system hard disk drive.
#>  
[CmdletBinding()]
Param()

    try 
    {
        if (Get-Module BitLocker)
        {
            Get-BitLockerVolume -MountPoint "$env:SystemDrive" | Select-Object -ExpandProperty ProtectionStatus -ErrorAction Stop
        }
        else
        {
            # log error
            $msg = "Module BitLocker not found"
            write-LogFile -Path $LogPath -name $LogName -message $msg -Level Warning
        }    
    }
    catch
    {
        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }   
}

function Get-MbamDiskProtectionStatus
{
<#
.Synopsis 
    Get the protection status of given hard disk drives
.DESCRIPTION
    Gets the protection status of given hard disk drives. 
.PARAMETER mountPoints
    An array of drives
.OUTPUTS
    One protection status per given mounting point entry
.EXAMPLE
    Get-DiskProtectionStatus ("C:","D:")
#>    
[CmdletBinding()]
[Parameter(Mandatory=$true)]
Param(
        [string[]]$mountPoints
    )


    try 
    {
        if (Get-Module BitLocker)
        {
            Get-BitLockerVolume -MountPoint $mountPoints | Select-Object -ExpandProperty ProtectionStatus -ErrorAction Stop
        }
        else
        {
            # log error
            $msg = "Module BitLocker not found"
            write-LogFile -Path $LogPath -name $LogName -message $msg -Level Warning
        }
    }
    catch
    {
        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }
}

function Get-MbamGpoRuleState
{
[CmdletBinding()]
Param(
        [Parameter(Mandatory=$true)]
        [string]$PolicyKey,

        [Parameter(Mandatory=$true)]
        [string]$PolicyValue,

        [Parameter(Mandatory=$true)]
        [string]$path
    )

    try
    {
        $result = Get-Item $path -ErrorAction Stop | Get-ItemProperty | Select-Object -ExpandProperty $PolicyKey

        if ($null -eq $result)
        {
            throw "Policy not found"
            # log error
            $msg = $_.Exception.toString()
            $msg += "; " + $_.ScriptStackTrace.toString()
            write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
        }

        if ($result -eq $PolicyValue)
        {
            return $true
        }
        else 
        {
            return $false
        }
    }
    catch
    {
        throw "Policy not found"
        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error     
    }
}

function Get-TpmObject
{
[CmdletBinding()]
Param()

    Get-CimInstance -Namespace ROOT\CIMV2\Security\MicrosoftTpm -Class Win32_Tpm

}

#endregion

#region 2.2 Server specific helpers
# ---------------------
#
# Section for helper functions targeting the backend
#===================================================

function Test-MbamWCFServiceState
{
<#
.Synopsis
    Tests the state of a WCF-service for MBAM.
.DESCRIPTION
    Tests the state of a Windows Communication Foundation service for MBAM. The following service types are possible
    admin:  for the administration service
    user:   for the user support service (deprecated)
    report: for the status report service
    core:   for the core service   
.PARAMETER serviceType
    Type of web service to test. Possible values are:
    admin  - for AdministrationService
    user   - for UserSupportService (deprecated)
    report - for StatusReportingService
    core   - for CoreService (RecoveryAndHardware)
.PARAMETER uri
.PARAMETER id
    An
.PARAMETER moduleId
    An optional ID referencing the calling module
.EXAMPLE
    Test-MBAMWCFServiceState -type admin -credentials domain\username
#>
[cmdletBinding()]
Param(
    # service type, accepted values are admin, user, report or core
    [Parameter(Mandatory=$true)]
    [ValidateSet('admin','user','report','core')]
    [String]$serviceType,

    [Parameter(Mandatory=$true)]
    [String]$uri,

    [Parameter(Mandatory=$true)]
    [String]$id,

    [String]$moduleId
)
    if($moduleId -eq "") {$moduleId = "N/A"}
    $obj = [TapResult]::New($id, $moduleId,"")

    Switch ($serviceType)
    {
        'admin' {
            $service = "MBAMAdministrationService/AdministrationService.svc"
            $obj.Task = "Webservice AdministrationService.svc running"}
        'user' {
            $service = "MBAMUserSupportService/UserSupportService.svc"
            $obj.Task = "Webservice UserSupportService.svc running"}
        'report' {
            $service = "MBAMComplianceStatusService/StatusReportingService.svc"
            $obj.Task = "Webservice StatusReportingService.svc running"}
        'core' {
            $service = "MBAMRecoveryAndHardwareService/CoreService.svc"
            $obj.Task = "Webservice CoreService(RecoveryAndHardware) running"}
        Default {$service = $null} #
    }

    Try
    {
        # we excpected this request to fail with a 401 because we do not pass any credentials
        Invoke-WebRequest -URI "$uri/$service" -ErrorAction Stop

        # We should not get to this point, otherwise the service is open to the world without checking credentials
        $obj.Status = "Missing login"
        $obj.Passed = 4
    }
    Catch 
    {
        # therefore a 401.2 exception should be raised
        if ($_.Exception -like "*(401) Unauthorized*")
        {
            $obj.Status = "Running"
            $obj.Passed = 1
        }  
        else
        {
            $obj.Status = "Not running"
            $obj.Passed = 2

            Write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error
        } 
    }

    Write-Output $obj    
}

function Get-MBAMHostname
{
<#
.Synopsis
    Gets the MBAM hostname.
.DESCRIPTION
    Gets the MBAM hostname from MBAM webadminstration (Get-MbamWebApplication -AdministrationPortal)
#>
[CmdletBinding()]
Param()

    try 
    {
        if(Get-Module Microsoft.MBAM)
        {
            Get-MBAMWebApplication -AdministrationPortal | Select-Object -ExpandProperty HostName -ErrorAction Stop
        }
        else
        {
            # log error
            $msg = "Module Microsoft.MBAM not found"
            write-LogFile -Path $LogPath -name $LogName -message $msg -Level Warning
        } 
    }
    catch
    {
        Write-Output ""
        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }
}

function Get-MBAMServerVersion25 
{
<#
.Synopsis
   Gets MBAM-Server version.
.DESCRIPTION
   Gets version number of the installed MBAM server software package.
#>  
[CmdletBinding()]
Param()
 
    try 
    {
        Get-Item 'HKLM:\SOFTWARE\Microsoft\MBAM Server' -ErrorAction Stop | Get-ItemProperty | Select-Object -ExpandProperty "Installed"
    }
    catch 
    {
       Write-Error("No MBAM-Server 2.5 SP1 installed.")
       Write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error
    }
}

#endregion

#region 2.3 General helpers
# -------------------
#
# Section for general functions
#==============================

function Test-CurrentUserAdmin
{
<#
.Synopsis
   Checks, if current user has the role administrator.
.DESCRIPTION
    Checks, if current user has the role administrator.
#>
    $objIdentitaet = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $objPrincipal = New-Object System.Security.Principal.WindowsPrincipal($objIdentitaet)
 
    if(-not $objPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) 
    {
            Write-Error "Current user is not an administrator"
            return $false
        }
    else
    {
        return $true
    }
}

#endregion

#endregion


#region 3 Report functions
# ------------------
#
# Section for all functions to create a report (format test 
# results, add special info section etc.
#
###############################################################



#region 3.1 Client specific report functions
# ------------------------------------
#
# Section for report functions targeting a client computer
#=========================================================

function Get-MbamClientEventLogEntry
{
<#
.SYNOPSIS
    Gets the last event log entries from the MBAM client event log.
.DESCRIPTION
    Gets the last event log entries from the MBAM client event log. By default it gets the last 10 log entry from admin and operational log
.PARAMETER quantity
    Count of last log entries fetched from MBMA client admin and operational log
#>
[CmdletBinding()]
Param(
    [int]$quantity = 10
)

    $result = ""

    # get MBAM admin log entries
    try
    {
        $mbamAdmin = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-MBAM/Admin"} -MaxEvents $quantity -ErrorAction Stop
        
        # list all admin log entries
        $result = "<p><strong>Admin log</strong></p>"
        $result += "<table><tr><td>Time</td><td>ID</td><td>Level</td><td>Message</td></tr>"

        foreach($entry in $mbamAdmin)
        {
            $result += "<tr><td>$($entry.TimeCreated)</td><td>$($entry.ID)</td><td>$($entry.LevelDisplayName)</td><td>$($entry.Message)</td></tr>"  
        }

        $result += "</table>"
    } 
    catch
    {
        $result += "<p><em>There is not an event log on the localhost computer that matches Microsoft-Windows-MBAM/Admin or the log is empty</em></p>"
    }

    # get MBAM operational log entries
    try
    {
        $mbamOperational = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-MBAM/Operational"} -MaxEvents $quantity -ErrorAction Stop
    
        # list all operational log entries
        $result += "<p><strong>Operational log</strong></p>"
        $result += "<table><tr><td>Time</td><td>ID</td><td>Level</td><td>Message</td></tr>"

        foreach($entry in $mbamOperational)
        {
            $result += "<tr><td>$($entry.TimeCreated)</td><td>$($entry.ID)</td><td>$($entry.LevelDisplayName)</td><td>$($entry.Message)</td></tr>"  
        }

        $result += "</table>"
    }
    catch
    {
        $result += "<p><em>There is not an event log on the localhost computer that matches Microsoft-Windows-MBAM/Operational or the log is empty</em></p>"
    }


    Write-Output $result
}

function Get-MbamClientConfiguration
{
<#
.SYNOPSIS
    Collects some configurations of the MBAM client agent.
.DESCRIPTION
    Collects some configurations of the MBAM client agent like report frequency or web service urls
.EXAMPLE
    PS C:\> Get-MbamClientConfiguration | fl

    Status Report Frequency         : 1
    Key Report Frequency            : 5
    Status Reporting Webservice Url : http://192.168.178.85:80/MBAMComplianceStatusService/StatusReportingService.svc
    Key Reporting Webservice Url    : http://192.168.178.85:80/MBAMRecoveryAndHardwareService/CoreService.svc
#>
[CmdletBinding()]
Param()

    $obj = New-Object PSCustomObject

    # Collect configuration and put it into the object
    $obj | Add-Member -MemberType NoteProperty -Name 'Status Report Frequency' -Value (Get-MbamStatusReportFrequency)
    $obj | Add-Member -MemberType NoteProperty -Name 'Key Report Frequency' -Value (Get-MbamKeyReportFrequency)
    $obj | Add-Member -MemberType NoteProperty -Name 'Status Reporting Webservice Url' -Value (Get-MbamStatusWebServiceUrl)
    $obj | Add-Member -MemberType NoteProperty -Name 'Key Reporting Webservice Url' -Value (Get-MbamKeyWebServiceUrl)

    Write-Output $obj
}

#endregion


#region 3.2 Server specific report functions
# ------------------------------------
#
# Section for report functions targeting the backend
#===================================================

function Send-MbamEmailOnError
{
    [CmdletBinding()]
    Param(
        $resultObjects,
        [bool]$useCredentials
    )

    foreach($obj in $resultObjects)
    {
        $send = $false

        if ($obj.passed -eq 2)
        {
            $subject = "[FAILED] MBAM server report"
            $send = $true
        }
        elseif ($obj.passed -eq 3)
        {
            $subject = "[WARNING] MBAM server report"
            $send = $true
        }
                elseif ($obj.passed -eq 3)
        {
            $subject = "[ERROR] MBAM server report"
            $send = $true
        }

        if ($send)
        {
            $body = $obj | ConvertTo-Html | Out-String

            if($useCredentials)
            {         
                Send-MailMessage -to $ConfigFile.Settings.Email.MailTo -from $ConfigFile.Settings.Email.MailFrom -Subject $subject -body $body -BodyAsHtml -Credential $ConfigFile.Settings.Email.User -SmtpServer $ConfigFile.Settings.Email.SMTPServer
            }
            else 
            {
                Send-MailMessage -to $ConfigFile.Settings.Email.MailTo -from $ConfigFile.Settings.Email.MailFrom -Subject $subject -body $body -BodyAsHtml -SmtpServer $ConfigFile.Settings.Email.SMTPServer
            }
        }        
    }
}

function Send-MbamEmailReport
{

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$body,

    [string] $subject = "MBAM server status report"
)

    Send-MailMessage -to $ConfigFile.Settings.Email.MailTo -from $ConfigFile.Settings.Email.MailFrom -Subject $subject -body $body -BodyAsHtml -SmtpServer $ConfigFile.Settings.Email.SMTPServer
}

function Send-MbamErrorMessage
{
<#
.Synopsis
   Sends an email with an error message.
.DESCRIPTION
   Sends an email message with an error message. The email is sent only if this specific error has not been send in the last $frequency minutes. 
   Emailsettings are read from the settings.psd1 file in the module directory. The frequency to send an email can be overwritten using the $frequency parameter. If 
   $frequency is <= zero, the standard value is taken.  
#>
[CmdletBinding()]
Param(
    # Recipient/s of mail
    [Parameter(Mandatory=$true)]
    [string[]]$To,

    # Subject of mail
    [Parameter(Mandatory=$true)]
    [string]$Subject,

    # Filename to store temporary data
    [Parameter(Mandatory=$true)]
    [string]$tmpFile,

    # Message about the error
    [string]$Body, 

    # Time in minutes in which a continuously occurring error is reported once
    [int]$Frequency
)

    # if frequency is set to zero or lower, Get standard value from stettings
    if ($Frequency -le 0)
    {
        $Frequency = $ConfigFile.Settings.Frequency
    }

    # Get the timestamp of last error mail
    try
    {
        $lastrun = Get-Content ($ConfigFile.Settings.TemporaryFilePath.ToString()+$tmpFile) -ErrorAction Stop
        $now = (Get-Date).AddMinutes(-$Frequency).ToFileTime()
    }
    catch
    {
        # last timestamp was not saved, so get a new one
        $lastrun = (Get-Date).ToFileTime()

        # check, if path for temporary files exists, otherwise create it
        if(!(Test-Path -Path $ConfigFile.Settings.TemporaryFilePath)){
            New-Item -ItemType directory -Path $ConfigFile.Settings.TemporaryFilePath
        }

        # create temporary file and write the timestamp
        New-Item ($ConfigFile.Settings.TemporaryFilePath.ToString()+$tmpFile) -type file -value $lastrun

        # set $now to a timestamp after $lastrun so that the mail is sent for the first time
        $now = (Get-Date).ToFileTime() 
    }


    if($lastrun -le $now)
    {
        try {
            $Credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ConfigFile.Settings.EmailSettings.User, (Get-Content $ConfigFile.Settings.EmailSettings.PasswordFile | ConvertTo-SecureString)
    
            Send-MailMessage -SmtpServer $ConfigFile.Settings.EmailSettings.SMTPServer -to $To -from $ConfigFile.Settings.EmailSettings.MailFrom -Subject $Subject -Body $Body -Credential $Credentials -Encoding $ConfigFile.Settings.EmailSettings.Encoding  
    
            Set-Content ($ConfigFile.Settings.TemporaryFilePath.ToString()+$tmpFile) (Get-Date).ToFileTime()
        }
        catch
        {
            write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error
        }
    }
}

#endregion


#region 3.3 General report functions
# ----------------------------
#
# Section for general report functions 
#=====================================

function Get-SystemOverview
{
<#
.SYNOPSIS
    Collects some system information.
.DESCRIPTION
    Collects some system information like hostname, model, bios, operating system etc.
.EXAMPLE
    PS C:\> Get-SystemOverview

    Host                 : WinSrv12-MBAM.corp.fbpro
    Manufacturer         : Microsoft Corporation
    Model                : Virtual Machine
    Type                 : x64-based PC
    OperatingSystem      : Microsoft Windows Server 2012 R2 Standard
    OSVersion            : 6.3.9600
    OSArchitecture       : 64-bit
    Last Boot Up Time    : 5/14/2018 11:24:07 AM
    Free Physical Memory : 0.5425 GB
    Free Disk Space      : 0.0705 GB
    Free Disk Space C    : 45.6102 GB
    Bios Manufacturer    : American Megatrends Inc.
    Bios Version         : 090007 
#>
[CmdletBinding()]
Param()

    $obj = New-Object PSCustomObject


    $obj | Add-Member -MemberType NoteProperty -Name 'Host' -Value ([System.Net.Dns]::GetHostByName(($env:computerName)) | Select-Object -ExpandProperty Hostname)
    $obj | Add-Member -MemberType NoteProperty -Name 'Manufacturer' -Value (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue| Select-Object -ExpandProperty Manufacturer)
    $obj | Add-Member -MemberType NoteProperty -Name 'Model' -Value (Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Model)
    $obj | Add-Member -MemberType NoteProperty -Name 'System Family' -Value (Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty SystemFamily -ErrorAction SilentlyContinue)
    $obj | Add-Member -MemberType NoteProperty -Name 'Type' -Value (Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty SystemType)
    $obj | Add-Member -MemberType NoteProperty -Name 'Bios Manufacturer' -Value (Get-CimInstance -ClassName Win32_BIOS | Select-Object -ExpandProperty Manufacturer)
    $obj | Add-Member -MemberType NoteProperty -Name 'Bios Version' -Value (Get-CimInstance -ClassName Win32_BIOS | Select-Object -ExpandProperty SMBIOSBIOSVersion)
    $obj | Add-Member -MemberType NoteProperty -Name 'Operating System' -Value (Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty Caption)
    $obj | Add-Member -MemberType NoteProperty -Name 'OS Version' -Value (Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty Version)
    $obj | Add-Member -MemberType NoteProperty -Name 'Release ID' -Value ((Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\" -Name ReleaseID -ErrorAction SilentlyContinue).ReleaseID)
    $obj | Add-Member -MemberType NoteProperty -Name 'OS Architecture' -Value (Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty OSArchitecture)
    $obj | Add-Member -MemberType NoteProperty -Name 'Last Boot Up Time' -Value (Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime)
    $obj | Add-Member -MemberType NoteProperty -Name 'Free Physical Memory' -Value ("{0:N4} GB" -f ((Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty FreePhysicalMemory)/1MB))
    
    foreach($volume in (Get-Volume | Where-Object DriveType -eq Fixed | Where-Object DriveLetter -ne $null))
    {
        $obj | Add-Member -MemberType NoteProperty -Name "Free Disk Space $($volume.DriveLetter)" -Value ("{0:N4} GB" -f ($volume.SizeRemaining/1GB))
    }

    Write-Output $obj
}

function ConvertTo-HtmlTable
{
<#
.SYNOPSIS
    Ouputs the note properties of an object in a html table.
.DESCRIPTION
    Ouputs the note properties of an object in a html table.
.PARAMETER inputObject
    The object to print in a html table
.PARAMETER cssClass
    An optional CSS class identifier
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true,ValueFromPipeline=$True)]
    $inputObject,
    [string]$cssClass
)
    Begin
    {
        if (($null -eq $cssClass) -or ($cssClass -eq ""))  
        {
            $result = "<table>"
        }
        else
        {
            $result ="<table class=`'$cssClass`'>" 
        }
    }

    Process
    {
        # 
        foreach($property in ($inputObject | Get-Member | Where-Object MemberType -like *property | Select-Object -ExpandProperty Name))
        {
            $result += "<tr><td>$property</td><td>$($inputObject.$property)</td></tr>"
        }
    }
    End
    {
        $result += "</table>"

        Write-Output $result
    }
}

function ConvertTo-TapResultHtmlTable 
{
<#
.Synopsis
    Converts one or many TapResult objects to a html table. 
.DESCRIPTION
    Converts one or many TapResult objects to a html table  with one result per row. 
    Newlines are converted into <br> (only in status column!).
#>
[CmdletBinding()]
Param(  
    [Parameter(
        Position=0, 
        Mandatory=$true, 
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)
    ]
    [Alias('Test result')]
    [TapResult[]]$inputObject
) 

    Begin 
    {
        Write-Output "<div style=`"overflow-x:auto;`"><table class=`"result-table`"><tr><th>ID</th><th>moduleID</th><th>Task</th><th>Status</th><th>Result</th></tr>"
        $nl = [System.Environment]::NewLine
    }
    
    Process 
    {   
        # Replace system new line with html br
        $status = ($inputObject.status).Replace($nl, "<br>")

        if ($inputObject.passed -eq 1)
        {
            Write-Output "<tr><td>$($inputObject.id)</td><td>$($inputObject.moduleID)</td><td>$($inputObject.task)</td><td>$status</td><td><span class=`"passed`">OK</span></td></tr>"
        }
        elseif ( ($inputObject.passed -eq 2) -or ($inputObject.passed -eq 4) )
        {
            Write-Output "<tr><td>$($inputObject.id)</td><td>$($inputObject.moduleID)</td><td>$($inputObject.task)</td><td>$status</td><td><span  class=`"failed`">!</span></td></tr>" 
        }
        elseif ($inputObject.passed -eq 3)
        {
            Write-Output "<tr><td>$($inputObject.id)</td><td>$($inputObject.moduleID)</td><td>$($inputObject.task)</td><td>$status</td><td><span  class=`"warning`">!</span></td></tr>" 
        }
    }

    End 
    {
        Write-Output "</table></div>"      
    }
}

function New-MBAMReportSectionHeader
{
<#
.Synopsis
    
.DESCRIPTION
    
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    $resultObjects,
        
    [Parameter(Mandatory=$true)]
    [string]$headertext,

    [string]$anchor
)

    $header = "<h3 id=`"$anchor`" class=`"passed`">$headertext</h3>"
    $errCounter, $warnCounter = 0, 0

    foreach($obj in $resultObjects)
    {
        if ( ($obj.passed -eq 2) -or ($obj.passed -eq 4) ) { $errCounter++ }
        if ($obj.passed -eq 3) { $warnCounter++ }
    } 
    
    if ($errCounter -gt 0) 
    { 
        $header = "<h3 id=`"$anchor`" class=`"failed`">$headertext (Errors: $errCounter)</h3>" 
    }
    elseif ($warnCounter -gt 0)
    {
        $header = "<h3 id=`"$anchor`" class=`"warning`">$headertext (Warnings: $warnCounter)</h3>"
    }
    
    Write-Output $header   
}

function New-MBAMReportNavPoint
{
<#
.Synopsis
    
.DESCRIPTION
    
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    $resultObjects,
        
    [Parameter(Mandatory=$true)]
    [string]$navPointText,
        
    [Parameter(Mandatory=$true)]
    [string]$anchor 
)

    $navPoint = "<li><a href=`"#$anchor`">$navPointText <span  class=`"green`">OK</span></a></li>"
    $errCounter, $warnCounter = 0, 0

    foreach($obj in $resultObjects)
    {
        if ( ($obj.passed -eq 2) -or ($obj.passed -eq 4) ) { $errCounter++ }
        if ($obj.passed -eq 3) { $warnCounter++ }
    } 
    
    if ($errCounter -gt 0) 
    { 
        $navPoint = "<li><a href=`"#$anchor`">$navPointText <span class=`"red`">$errCounter</span></a></li>" 
    }
    elseif ($warnCounter -gt 0)
    {
        $navPoint = "<li><a href=`"#$anchor`">$navPointText <span class=`"orange`">$warnCounter</span></a></li>"
    }
    
    Write-Output $navPoint  
}

function Get-PSVersionAsHtmlTable
{
[CmdletBinding()]
Param(
    [string]$cssClass
)
    if (($null -eq $cssClass) -or ($cssClass -eq "")) { $result = "<table>" }
    else { $result ="<table class=`'$cssClass`'>" }
    $result += "<tr><td>PowerShell Version</td><td>$($PSVersionTable.PSVersion.ToString())</td></tr>"
    $result += "<tr><td>PowerShell Edition</td><td>$($PSVersionTable.PSEdition.ToString())</td></tr>"
    $result += "<tr><td>Build Version</td><td>$($PSVersionTable.BuildVersion.ToString())</td></tr>"
    $result += "<tr><td>CLR Version</td><td>$($PSVersionTable.CLRVersion.ToString())</td></tr>"
    $result += "<tr><td>WS Man Stack Version</td><td>$($PSVersionTable.WSManStackVersion.ToString())</td></tr>"
    $result += "<tr><td>PowerShell Remoting Protocol Version</td><td>$($PSVersionTable.PSRemotingProtocolVersion.ToString())</td></tr>"
    $result += "<tr><td>Serialization Version</td><td>$($PSVersionTable.SerializationVersion.ToString())</td></tr>"
    $result += "</table>"

    Write-Output $result
}

#endregion


#endregion



# Export functions and variables, access is restricted by manifest file if needed
Export-ModuleMember -Function '*'
Export-ModuleMember -Variable '*'