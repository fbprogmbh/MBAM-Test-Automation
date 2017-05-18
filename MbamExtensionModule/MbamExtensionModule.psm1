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
    Date:             12/23/2016
    Last change:      05/18/2017
    Version:          0.8

#>

<#

    Import modules
    ==============        

#>

# Check, if necessary module are available and imported, if not, import them

if ((Get-Module -List Microsoft.PowerShell.Security) -and !(Get-Module Microsoft.PowerShell.Security))
{
    Import-Module Microsoft.PowerShell.Security
}

if ((Get-Module -List Microsoft.MBAM) -and !(Get-Module Microsoft.MBAM))
{
    Import-Module Microsoft.MBAM
}

if ((Get-Module -List ActiveDirectory) -and !(Get-Module ActiveDirectory))
{
    Import-Module ActiveDirectory
}

if ((Get-Module -List BitLocker) -and !(Get-Module BitLocker))
{
    Import-Module BitLocker
}

if ((Get-Module -List TrustedPlatformModule) -and !(Get-Module TrustedPlattformModule))
{
    Import-Module TrustedPlatformModule
}
##################################################################

# Load settings from setting file
$ConfigFile = Import-LocalizedData -FileName Settings.psd1


# Set the path and name of standard log file to path and name configured in settings
$LogPath = $ConfigFile.Settings.LogFilePath
$LogName = (Get-date -Format "yyyyMMdd")+"_"+$ConfigFile.Settings.LogFileName



# Helper functions
# ----------------
<#

 Some functions used in other functions in this module.

#>

function Get-OperatingSystemInfo
{
<#
.Synopsis
   Gets a bunch of system information.
.DESCRIPTION
   Gets a bunch of system information like free RAM, free disk space, OS version etc.
#>

    Get-CimInstance Win32_OperatingSystem | select *
}

function Get-SystemStartupTime
{
<#
.Synopsis
   Gets the time of last system start up.
.DESCRIPTION
   Looks up for the last system startup by checking the event log for id 6005.
.EXAMPLE
   PS C:\Get-SystemStartupTime
   
   Freitag, 30. Dezember 2016 09:03:08
#>
   
    # Get log record with id 12 of source kernel general and return time
    Get-winevent -FilterHashtable @{Logname='System'; ProviderName='Microsoft-Windows-Kernel-General'; ID=12} -MaxEvents 1 | select @{label='TimeCreated';expression={$_.TimeCreated.ToString("yyyy-M-d HH:mm:ss")}} -ExpandProperty TimeCreated

}

function Get-EventLogErrorDetails
{
<#
.Synopsis
   Gets detailed information about a event log entry with given record ID.
.DESCRIPTION
   Gets detailed information about a event log entry and returns it as a single string. The event log entry is determined by the channelname and the record ID.
.OUTPUTS 
    Object.String returns a single string c
#>

    [CmdletBinding()]
    Param(
        # Record ID of logged event
        [int]$eventRecordID,
        # Channel in which event was logged
        [string]$eventChannel
    )

    $event = Get-WinEvent -LogName $eventChannel -FilterXPath "<QueryList><Query Id='0' Path='$eventChannel'><Select Path='$eventChannel'>*[System[(EventRecordID=$eventRecordID)]]</Select></Query></QueryList>"

    $2nl = [System.Environment]::NewLine + [System.Environment]::NewLine

    $Body = $event.TaskDisplayName + $2nl
    $Body += "Host: " + $event.MachineName + $2nl
    $Body += $event.TimeCreated
    $body += $2nl + $event.FormatDescription()

    Write-Output $Body
}

function Test-MbamSQLServerConnection
{
    [CmdletBinding()]
    Param(
        # IP-address or DNS of destination
        [Parameter(Mandatory=$true)]
        [string]$destination
    )

    $obj = New-Object PSObject
        
    try 
    {
            $result = Test-Connection $destination 

            if ($result -ne $null)
            {
                $obj | Add-Member NoteProperty Status("Reachable")
                $obj | Add-Member NoteProperty Passed("true")
            }
            else
            {
                $obj | Add-Member NoteProperty Status("Not reachable")
                $obj | Add-Member NoteProperty Passed("false")
            }
        }
    catch
    {
            # log error
            $msg = $_.Exception.toString()
            $msg += "; " + $_.ScriptStackTrace.toString()
            write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
        }

    Write-Output $obj
}

function Get-LastSoftwareUpdateTimes
{
<#
.Synopsis
   Gets the times of the last software updates including update titles and descriptions
.DESCRIPTION
   Gets the times of the last software updates including update titles and descriptions which are installed via MSI. By default 
   it checks the last 5 system updates and returns these if they have a status of Succeeded or SucceededWithErrors.
   This can be changed to a value between 1 to 30 entries.
.OUTPUTS
    PSObject with Properties
    [DateTime] InstalledOn - Installation date
    [String] Title - Short sescription of update
    [string] Description - Long description of update
    [int32] Status - status of update: 2 = succeeded; 3 = succeeded with errors
#>
    [CmdletBinding()]
    Param(
        [int]$count = 5
    )

    if ($count -le 0 -OR $count -gt 30)
    {
            $count = 5
        }

    $Session = New-Object -ComObject Microsoft.Update.Session            
    $Searcher = $Session.CreateUpdateSearcher() 
        
    # http://msdn.microsoft.com/en-us/library/windows/desktop/aa386532%28v=vs.85%29.aspx
    # get the last five update entrys in case one is not succeded            
    $Searcher.QueryHistory(0,5) | ForEach-Object {
            # http://msdn.microsoft.com/en-us/library/windows/desktop/aa387095%28v=vs.85%29.aspx  
            if ($_.ResultCode -eq 2 -OR $_.ResultCode -eq 3)
            {
                if($_.Title -match "\(KB\d{6,7}\)"){            
                    # Split returns an array of strings            
                    $Title = ($_.Title -split '.*(KB\d{6,7})\)')            
                }else{            
                    $Title = $_.Title            
                }      
                return New-Object -TypeName PSObject -Property @{            
                    InstalledOn = Get-Date -Date $_.Date;            
                    Title = $Title;            
                    Description = $_.Description;            
                    Status = $_.ResultCode            
                }
            }
        } 
}

function Get-TpmObject
{

    Get-wmiobject -Namespace ROOT\CIMV2\Security\MicrosoftTpm -Class Win32_Tpm

}

function Test-UserRights
{
    $objIdentitaet = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $objPrincipal = New-Object System.Security.Principal.WindowsPrincipal($objIdentitaet)
 
    if(-not $objPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) 
    {
            Write-Error "Missing rights - admin rights necessary!"
            return $false
        }
    else
    {
            return $true
        }
}

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

        if ($obj.passed -eq "false")
        {
            $subject = "[ERROR] MBAM server report"
            $send = $true
        }
        if ($obj.passed -eq "warning")
        {
            $subject = "[WARNING] MBAM server report"
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

function Get-LocalAdmins
{
<#
.Synopsis
   Gets all users in local group "Administrators".
.DESCRIPTION
   Gets all users in local group "Administrators". Local groups inside are not recursively resolved into their users. Groupnames will be placed in result as if they were users.
   Active Directory groups on the other hand are recursively resolved for other their users and maybe other groups inside.  
.OUTPUTS
    SamAccountNames of users
#>

    $Computer = $env:COMPUTERNAME

    $ADSIComputer = [ADSI]("WinNT://$Computer,computer")

    try 
    {
        $group = $ADSIComputer.psbase.children.find('Administrators', 'Group')
    }
    catch
    {
        try 
        {
            $group = $ADSIComputer.psbase.children.find('Administratoren', 'Group')
        }
        catch
        {
        }
    }

    $members = $group.psbase.invoke("members")  | ForEach {
        $_.GetType().InvokeMember("Name",  'GetProperty',  $null,  $_, $null)
    }
    $admins = @()

    if(Get-Module ActiveDirectory)
    {
        foreach($member in $members)
        {  
            try {      
                # Try if $member is a AD group and get all members of this group including all nested groups      
                $admins += (Get-ADGroupMember $member -Recursive | select -ExpandProperty SamAccountName)
            }
            catch
            {
                # TODO catch unterscheiden nach nicht gefunden oder active directory Fehler
                # If it is not a AD group, it has to be a local account, so add it (we assume local groups are not used inside the company)
                $admins += $member
            }
        }
    }
    # Remove duplicated accounts und output the unique ones
    Write-Output $admins | select -Unique
}

function Get-LastInstalledUpdateGroup
{

    $InstalledUpdates = Get-WinEvent -FilterHashtable @{ProviderName='Microsoft-Windows-WindowsUpdateClient';Id=19} | Select-Object -Property *,@{Name='UpdateName';Expression={$_.Properties[0].Value}} | Select-Object TimeCreated, UpdateName
    $date = $InstalledUpdates.TimeCreated | Select-Object -First 1

    $LastInstalledUpdates = @()

    foreach($update in $InstalledUpdates)
    {
        if ($update.TimeCreated.Date -eq $date.Date)
        {
            $LastInstalledUpdates += $update
        }
        else
        {
            break;
        }
    }

    Write-Output $LastInstalledUpdates
}

function Get-LastInstalledSccmUpdateGroup
{
    try
    {
        $AssignedUpdateCIs = Get-CimInstance -Namespace root\ccm\Policy\Machine -ClassName CCM_UpdateCIAssignment -ErrorAction Stop | Select-Object -ExpandProperty AssignedCIs | ForEach-Object { ([XML]$_).CI } | Select-Object -Property @{Name='UpdateId';Expression={$_.ID}},DisplayName 
        $InstalledUpdates = Get-WinEvent -FilterHashtable @{ProviderName='Microsoft-Windows-WindowsUpdateClient';Id=19} | Select-Object -Property *,@{Name='UpdateName';Expression={$_.Properties[0].Value}},@{Name='UpdateId';Expression={$_.Properties[1].Value}}
        
        $UpdatesAssignedAndInstalled = Compare-Object -ReferenceObject $AssignedUpdateCIs -DifferenceObject $InstalledUpdates -Property UpdateId -IncludeEqual | Where-Object { $_.SideIndicator -eq '==' } | Select-Object -ExpandProperty UpdateId
        $InstalledUpdates = $InstalledUpdates | Where-Object { $UpdatesAssignedAndInstalled -contains $_.UpdateId } | Select-Object -Property TimeCreated,UpdateName

        $date = $InstalledUpdates.TimeCreated | Select-Object -First 1

        $LastInstalledUpdates = @()

        foreach($update in $InstalledUpdates)
        {
        if ($update.TimeCreated.Date -eq $date.Date)
        {
            $LastInstalledUpdates += $update
        }
        else
        {
            break;
        }
    }

        Write-Output $LastInstalledUpdates
    }
    catch
    {      
        write-LogFile -Path $LogPath -name $LogName -message "CCM class not found. SCCM client not installed?" -Level Error
        Throw "SCCM client not installed"
    }
}

function Get-FormattedUpdateInformation
{
    $updates = Get-LastInstalledUpdateGroup
    
    if ($updates -eq $null)
    {
        Write-Output "No updates found"
    }
    else
    {
        Write-Output $updates[0].TimeCreated
        Write-Output "<ul>"

        foreach($update in $updates)
        {
            Write-Output "<li>"$update.UpdateName"</li>"
        }
        Write-Output "</ul>"
    }
}

function Get-FormattedSccmUpdateInformation
{
    try
    {
        $updates = Get-LastInstalledSccmUpdateGroup -ErrorAction Stop
    
    
        if ($updates -eq $null)
        {
            Write-Output "No updates found"
        }
        else
        {
            Write-Output $updates[0].TimeCreated"<br/><br/>"
            Write-Output "<ul>"

            foreach($update in $updates)
                    {
            Write-Output "<li>"$update.UpdateName"</li>"
        }
            Write-Output "</ul>"
        }
    }
    catch
    {
        Write-Output "SCCM client not installed"
    }
}

function Get-UpdateHistory 
{
    [CmdletBinding()]
    Param(
        [int]$number = 20
    )

    Get-WinEvent -FilterHashtable @{ProviderName='Microsoft-Windows-WindowsUpdateClient';Id=19} | Select-Object -Property *,@{Name='UpdateName';Expression={$_.Properties[0].Value}} | Select-Object TimeCreated, UpdateName -First $number
}

function Get-SccmDeploymentHistory
{
    [CmdletBinding()]
    Param(
        [int]$number = 20
    )

    try
    {
        Get-CimInstance -Namespace root\ccm\Policy\Machine -ClassName CCM_UpdateCIAssignment -ErrorAction Stop `
        | Select-Object -Property AssignmentName,EnforcementDeadline,StartTime -First $number `
        | Sort-Object -Property EnforcementDeadline -Descending `   
    }
    catch
    {
        # log error 
        write-LogFile -Path $LogPath -name $LogName -message "CCM_UpdateCIAssignment class not found" -Level Error
    }
}

function Test-SystemRestartMayBeNescessary
{
    [Cmdletbinding()]
    Param(
        [int]$withinDays = 7
    )

    # If we have a pending reboot, system definitely has to restart
    if (Get-PendingReboot)
    { Write-Output "yes" }

    # Otherwise check, if there are updates to install within the next $withDays
    else
    {
        try
        {
            $date = (Get-Date).AddDays($withinDays)
        
            Get-CimInstance -Namespace 'root\ccm\ClientSDK' -ClassName 'CCM_SoftwareUpdate' -ErrorAction Stop `
            | select -ExpandProperty Deadline `            | ForEach-Object { if ($_.Deadline -le $date) { Write-Output "yes" } else { Write-Output "no" } }

        }
        catch
        {
            Write-Output "SCCM client not installed"
            # log error
            write-LogFile -Path $LogPath -name $LogName -message "CCm class not found. SCCM client not installed?" -Level Error
        }
    }
}

function Get-MaintenanceMode
{
<#
.Synopsis
    Gets maintenance status of host (needs MMTool to be available).
.DESCRIPTION
    Gets maintenance status of host. It checks for logfile of MMTool and parses the info inside to decide, if maintenance mode is on ($true)
    or off ($false).
    If file is not found because maybe MMTool is not installed, it also returns $false. 
.OUTPUTS
    $true if maintenance mode is on, $false otherwise 
#> 

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$pathToLog
    )

    try
    {
        $maintenanceOn = $false
        
        # Get content of MMTool logfile
        $file = Get-Content $pathToLog

        # Get last line number 
        $lastLine = $file.Count-1
        # Get actual date and time
        $now = Get-Date

        # Check if last entry in file is an info about end time of maintenance mode or if maintenance mode is still on till xx:xx:xx
        if (($file[$lastLine] -like "*Maintenance -> End*") -or ($file[$lastLine] -like "*Maintenance Mode bis*"))
        {
            # Get date and time from the string
            $date = Get-Date($file[$lastLine].Substring($file[$lastLine].Length-19, 19))     
        }
        
        # Check if last entry in file is a entry about a manually ended maintenance mode
        elseif ($file[$lastLine] -like "*Maintenance*ausgeschaltet*") 
        { 
            # Get date and time from the string
            $date = Get-Date($file[$lastLine-1].Substring($file[$lastLine-1].Length-19, 19))
        }

        if ($date)
        {
            # Check if we are still in maintenance mode or not
            if ($date -gt $now) { $maintenanceOn = $true }
        }

        return $maintenanceOn
    }
    catch
    {
        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error

        return $false
    }
}

function Get-PendingReboot
{
<#
.Synopsis
    Checks if there is a reboot pending
.DESCRIPTION
    This function looks for a registry branch wiht the ending RebootPending. If it does not exists, then no reboot is necessary.   
.OUTPUTS
    $true if reboot is pending, $false otherwise 
#> 

    $reboot = $false

    try 
    {
        if (Get-item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction Stop)
        {
            $reboot = $true
        }
    }
    catch 
    {
        # We do not log anything at this point because in case of an error there is just no reboot pending
    }

    return $reboot
}

function Get-UserLoginHistory
{
<#
.Synopsis
    Gets user login history on machine.
.DESCRIPTION
    Gets user login history on machine within last 7 days by default.  
    
    Logon Types
    ===========
    2  = Logon Typ 2  - Interactive
    3  = Logon Typ 3  - Network
    4  = Logon Typ 4  - Batch
    5  = Logon Typ 5  - Service
    7  = Logon Typ 7  - Unlock
    8  = Logon Typ 8  - NetworkCleartext
    9  = Logon Typ 9  - New Credentials
    10 = Logon Typ 10 - RemoteInteractive
    11 = Logon Typ 11 - CachedInteractive

.PARAMETERS
    $date The date of from which logins are returned    
.OUTPUTS
    
#>

    [CmdletBinding()]
    Param(
        [DateTime]$startDate = (Get-Date).AddDays(-7)
    )

    
    $log = Get-Eventlog -LogName Security -after $startDate

    #$log | where {$_.EventID -eq 4624} | where {($_.ReplacementStrings[8] -eq 2) -or ($_.ReplacementStrings[8] -eq 10)} | select {$_.ReplacementStrings[5], $_.ReplacementStrings[18]}

    #$log | where {$_.EventID -eq 4624} | where {($_.ReplacementStrings[8] -eq 2) -or ($_.ReplacementStrings[8] -eq 10)} | Select-Object -unique  -ExpandProperty ReplacementStrings | select -Index 5,16
    #$log | where {$_.EventID -eq 4624} | where {($_.ReplacementStrings[8] -eq 2) -or ($_.ReplacementStrings[8] -eq 10)}  | foreach {write-ouput $_.TimeGenerated $_.ReplacementStrings[5]} 
    $log | where {$_.EventID -eq 4624} | where {($_.ReplacementStrings[8] -eq 2) -or ($_.ReplacementStrings[8] -eq 10)}  | foreach {
        $obj = New-Object PSObject 
        $obj | Add-Member NoteProperty LogonTime($_.TimeGenerated)
        $obj | Add-Member NoteProperty User($_.ReplacementStrings[5])
        if ($_.ReplacementStrings[8] -eq 2)
        {
            $obj | Add-Member NoteProperty LogonTyp("Interactive")
        }
        else
        {
            $obj | Add-Member NoteProperty LogonTyp("RemoteInteractive")
            $obj | Add-Member NoteProperty IP-Adresse($_.ReplacementStrings[18])
            }
        
       Write-Output $obj
    } | where {$_.User -notlike "DWM-*"}

}


# Report Functions
# ----------------
<#
    Some functions used for reporting, building reports or convert results to html tables.
#>

function ConvertTo-HtmlTable 
{
<#
.Synopsis
    Converts one or many MBAM Testresult-Objects to a html table 
.DESCRIPTION
    Converts one or many MBAM Testresult-Objects to a html table with one result per row. 
    Newlines are converted into <br> (only in status column!)
#>
    Param(  
        [Parameter(
            Position=0, 
            Mandatory=$true, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true)
        ]
        [Alias('Testresult')]
        [PSCustomObject[]]$TestResultObject
    ) 

    Begin 
    {
        Write-Output "<div style=`"overflow-x:auto;`"><table class=`"result-table`"><tr><th>Name</th><th>Task</th><th>Status</th><th>Result</th></tr>"
        $nl = [System.Environment]::NewLine
    }
    
    Process 
    {   
        # Replace system new line with html br
        $status = ($TestResultObject.status).Replace($nl, "<br>")

        if ($TestResultObject.passed -eq "true")
        {
            Write-Output "<tr><td>"$TestResultObject.name"</td><td>"$TestResultObject.task"</td><td>$status</td><td><span class=`"passed`">OK</span></td></tr>"
        }
        elseif ($TestResultObject.passed -eq "false")
        {
            Write-Output "<tr><td>"$TestResultObject.name"</td><td>"$TestResultObject.task"</td><td>$status</td><td><span  class=`"failed`">!</span></td></tr>" 
        }
        elseif ($TestResultObject.passed -eq "warning")
        {
            Write-Output "<tr><td>"$TestResultObject.name"</td><td>"$TestResultObject.task"</td><td>$status</td><td><span  class=`"warning`">!</span></td></tr>" 
        }
    }
    End 
    {
        Write-Output "</table></div>"      
    }
}

function New-MbamReportSectionHeader
{
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
        if ($obj.passed -eq "false") { $errCounter++ }
        if ($obj.passed -eq "warning") { $warnCounter++ }
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

function New-MbamReportNavPoint
{
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
        if ($obj.passed -eq "false") { $errCounter++ }
        if ($obj.passed -eq "warning") { $warnCounter++ }
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

function Get-MbamClientSecurityStatus
{
    Test-MbamOSDiskProtectionStatus
    Test-MbamDriveProtectionStatus
}

function Get-MbamClientApplicationStatus
{

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$agentVersion
)

Test-MbamClientSoftwareState
Test-MbamClientAgentServiceState
Test-MbamClientAgentVersion $agentVersion
Test-MbamClient2ServerStatusReporting
Test-MbamClient2ServerKeyReporting
    
}

function Get-MbamClientInfrastructureStatus
{

    if (Get-Module -Name TrustedPlatformModule)
    {
        Test-MbamTPMStatus
    }
    else
    {
        # log error
        $msg = "Module TrustedPlatformModule not found, skipping TPM tests."
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Warning
    }
    Test-MbamTpmOwnerShip
    Test-MbamTpmVersion

}

function New-MbamClientHtmlStatusReport
{
<#
.Synopsis
    Creates a report with an overview of a MBAM clients status.
.DESCRIPTION
    Creates a report with an complete overview of a MBAM clients status. It gives a short info about the host followed by resluts of the application and securtiy checks. 
.OUTPUTS
    A HTML Report.
.EXAMPLE
    PS C:\ New-MbamClientHtmlStatusReport -title "My Report" -agentVersion "2.5.1126.0"
#>
    [CmdletBinding()]
    Param(
        [string]$title ="Mbam report",

        [Parameter(Mandatory=$true)]
        [string]$agentVersion
    )


        $date = Get-Date -Format g
        $currentHost = [System.Net.Dns]::GetHostByName(($env:computerName)) | select -ExpandProperty Hostname
        $osInfo = Get-OperatingSystemInfo
        $lastBootUpTime = Get-SystemStartupTime
        $freeRAM = "{0:N3}" -f ($osInfo.FreePhysicalMemory/1MB)
        $freeDiskSpace = "{0:N1}" -f ((get-WmiObject win32_logicaldisk | where DeviceID -eq "C:" | select -ExpandProperty FreeSpace)/1GB)
        $logo = $ConfigFile.Settings.Logo
        
        Write-Output "<!DOCTYPE html>
        <html>
            <head>
                <title>$title</title>
                <style>
                    html {margin: 0; padding: 0;}
                    body {font-size: 14px; margin: 0; padding: 0 0 10px 0;}
                    h1 {color: #fff;}
                    h1 span {text-transform: uppercase;}
                    h3 {margin-top: 40px; padding: 5px; max-width: 40%; text-transform: uppercase; background-color: #33cc33;}
                    h1, h2,h3, p, table, img {margin-left: 20px;}
                    p {font-size: 16px;}
                    table {width: 80%; border: 1px solid darkgrey; border-collapse: collapse;font-family: Arial, sans-serif;}
                    table.info {max-width: 600px; border: 1px solid black; border-collapse: collapse;font-family: Courier, sans-serif;}
                    th {background-color: #d6d6c2; color: white; text-transform: uppercase; font-size: 1.5em; border-bottom: 1px solid darkgray;}
                    th, td {padding: 5px 10px; text-align: left;}
                    tr:nth-child(even) {background-color: #e6e6e6;}
                    tr:hover {background-color: #a6a6a6;}
                    td:first-child {width: 120px;}
                    td:nth-child(3) {width: 200px;}
                    td:last-child {width: 100px;}
                    table.info td:first-child {width: 180px;}
                    .header {background-color: #bfbfbf; width: 100%; padding: 20px 0;}
                    .header img {text-align: center;}
                    .passed {background-color: #33cc33; color: #fff;}
                    .failed {background-color: #cc0000; color: #fff;}
                    .warning {background-color: #ff9933; color: #fff;}
                    .hostname {color: #3366ff; font-weight: bold;}
                    span.passed, span.failed, span.warning {display: block; padding: 5px; border-radius: 30px; width: 25px; text-align: center; font-weight: bold; margin: auto;}
                </style>
            </head>
            <body>
                <div class=`"header`">
                    <img src=`"$logo`">
                    <h1><span>Microsoft Bitlocker</span> Administration and Monitoring</h1>
                </div>
                <h2>Client statusreport</h2>

                <p>Report created at $date on <span class=`"hostname`">$currentHost</span></p>
                
                <table class=`"info`">
                    <tr>
                        <td>Host:</td>
                        <td>$currentHost</span>
                    </tr>
                    <tr>
                        <td>Operating System:</td>
                        <td>"$osInfo.Caption"</span>
                    </tr>
                    <tr>
                        <td>OS version:</td>
                        <td>"$osInfo.Version"</span>
                    </tr>
                    <tr>
                        <td>Last boot up time:</td>
                        <td>$LastBootUpTime</span>
                    </tr>
                    <tr>
                        <td>OS architecture:</td>
                        <td>"$osInfo.OSArchitecture"</span>
                    </tr>
                    <tr>
                        <td>Free physical memory (GB):</td>
                        <td>$freeRAM</span>
                    </tr> 
                    <tr>
                        <td>Free disk space (GB):</td>
                        <td>$freeDiskSpace</span>
                    </tr>                
                </table>"

        # Get and output infrastructure status
        $status = Get-MbamClientInfrastructureStatus
        if ($status -ne $null)
        {
            $header = "<h3>Infrastructure status:</h3>"
            
            foreach($o in $status)
            {
                if($o.passed -eq "false")
                { 
                    $header = "<h3 class=`"failed`">Infrastructure status:</h3>"
                    break
                }
                if($o.passed -eq "warning")
                { 
                    $header = "<h3 class=`"warning`">Infrastructure status:</h3>"
                }
            }
            Write-Output $header
            $status | ConvertTo-HtmlTable
        }

        # Get and output Mbam appliciation status
        $status = Get-MbamClientApplicationStatus $agentVersion
        if ($status -ne $null)
        {
            $header = "<h3>Application status:</h3>"
            
            foreach($o in $status)
            {
                if($o.passed -eq "false")
                { 
                    $header = "<h3 class=`"failed`">Application status:</h3>"
                    break
                }
                if($o.passed -eq "warning")
                { 
                    $header = "<h3 class=`"warning`">Application status:</h3>"
                }
            }

            Write-Output $header
            $status | ConvertTo-HtmlTable
        }

        # Get and output security status
        $status = Get-MbamClientSecurityStatus
        if ($status -ne $null)
        {
            $header = "<h3>Security Status:</h3>"
            
            foreach($o in $status)
            {
                if($o.passed -eq "false")
                { 
                    $header = "<h3 class=`"failed`">Security status:</h3>"
                    break
                }
                if($o.passed -eq "warning")
                { 
                    $header = "<h3 class=`"warning`">Security status:</h3>"
                }
            }

            Write-Output $header
            $status | ConvertTo-HtmlTable
        }

        # Get and output GPO status
        $status = Test-MbamGpos
        if ($status -ne $null)
        {
            $header = "<h3>Group Policy Status:</h3>"
            
            foreach($o in $status)
            {
                if($o.passed -eq "false")
                { 
                    $header = "<h3 class=`"failed`">Group policy status:</h3>"
                    break
                }
                if($o.passed -eq "warning")
                { 
                    $header = "<h3 class=`"warning`">Group policy status:</h3>"
                }
            }

            Write-Output $header
            $status | ConvertTo-HtmlTable
        }
 
}



<#
    Server functions
    ======================================================================
#>

function Get-ComplianceDBConnectState
{
<#
.Synopsis
   Get state of administration-website application (complianc database).
.DESCRIPTION
   Get state of the administration-website application and its connection status to the compliance database.
   Therefore the last system startup is determined and afterwards the event log of Mbam-web/operational is checked for an event with ID 200 that contains the expression "Compliance database" in the message.
   Until the website is not access since the last system reboot, no event log records will be created and therefore the function will return a "not found".
.OUTPUTS
   System.String returns a string with current connection status ("connected", "not connected" or "not found")
.EXAMPLE
   PS C:\ Get-ComplianceDBConnectState
   Connected
#>
 
    $lastStartup = Get-SystemStartupTime

    try
    {
        $connected = Get-WinEvent -FilterHashtable @{logname="microsoft-windows-Mbam-web/operational";StartTime=$lastStartup;} -ErrorAction Stop | where {$_.Message -Like "*Compliance database*" -and $_.ID -eq 200} 

        if ($connected -ne $null)
        {
            Write-Output("Connected")
        }
        else 
        {
            Write-Output("Not connected")
        }
    }
    catch 
    {
        Write-Output("Not found")
        Write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error
    }
    
}

function Get-RecoveryDBConnectState
{
<#
.Synopsis
    Get state of administration-website application (recovery database).
.DESCRIPTION
   Get state of the administration-website application and its connection status to compliance database to the recovery database.
   Therefore the last system startup is determined and afterwards the event log of Mbam-web/operational is checked for an event with ID 200 that contains the expression "Recovery database" in the message.
   Until the website is not access since the last system reboot, no event log record will be created and therefore the function will return a "not found"
.OUTPUTS
   System.String returns a string with current connection status ("connected", "not connected" or "not found")
.EXAMPLE
   PS C:\ Get-RecoveryDBConnectState
   Connected
#>
       
    $lastStartup = Get-SystemStartupTime

    try 
    {
        $connected = Get-WinEvent -FilterHashtable @{logname="microsoft-windows-Mbam-web/operational";StartTime=$lastStartup;} -ErrorAction Stop | where {$_.Message -Like "*Recovery database*" -and $_.ID -eq 200}

        if ($connected -ne $null)
        {
            Write-Output("Connected")
        }
        else 
        {
            Write-Output("Not connected")
        }
    }
    catch 
    {
        Write-Output("Not found")
        Write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error
    }
    
}

function Get-MbamHelpDeskSPNState
{
<#
.Synopsis
   Get if the HelpDesk has its Service Principal Name registered successfully.
.DESCRIPTION
   Get if the HelpDesk has its Service Principal Name registered successfully. Therefore the event log is checked for a record with ID 202 and message containing the phrase "HelpDesk" 
   which was created after last system startup. If the HelpDesk website is not access since last startup, no record is created and the function will return "Not found" 
.OUTPUTS
    System.String returns a string with the SPN registration status ("Registered" or "Not found")
.EXAMPLE
    PS C:\ Get-MbamHelpDeskSPNState
    Registered
#>  

    $lastStartup = Get-SystemStartupTime

    try
    {
        $SPNregistered = Get-WinEvent -FilterHashtable @{logname="microsoft-windows-Mbam-web/operational";StartTime=$lastStartup;} -ErrorAction stop | where {$_.Message -Like "*HelpDesk*" -and $_.ID -eq 202}

        # service is registered, ohterwise, an ObjectNotFound exception is thrown
        Write-Output("Registered")
    }
    catch
    {
        # no registration logged since last startup 
        Write-Output("Not found")
        Write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error
    }
    
}

function Get-MbamSelfServiceSPNState
{
<#
.Synopsis
   Get if the SelfService Portal has its Service Principal Name registered successfully.
.DESCRIPTION
   Get if the SelfService Portal has its Service Principal Name registered successfully. Therefore the event log is checked for a record with ID 202 and message containing the phrase "SelfService" 
   which was created after last system startup. If the HelpDesk website is not access since last startup, no record is created and the function will return "Not found" 
.OUTPUTS
    System.String returns a string with the SPN registration status ("Registered" or "Not found")
.EXAMPLE
    PS C:\ Get-MbamSelfServiceSPNState
    Registered
#>   

    $lastStartup = Get-SystemStartupTime

    try
    {
        $SPNregistered = Get-WinEvent -FilterHashtable @{logname="microsoft-windows-Mbam-web/operational";StartTime=$lastStartup;} -ErrorAction stop | where {$_.Message -Like "*SelfService*" -and $_.ID -eq 202}

        # portal is registered, ohterwise an ObjectNotFound exception is thrown
        Write-Output("Registered") 
    }
    catch
    {
        # no registration logged since last startup
        Write-Output("Not found")
        Write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error
    }  
}

function Get-MbamWCFServiceState
{
<#
.Synopsis
   Get the state of a WCF-service for Mbam.
.DESCRIPTION
   Get the state of a Windows Communication Foundation service for Mbam. The following service types are possible
   admin:  for the administration service
   user:   for the user support service
   report: for the status report service
   core:   for the core service
#>
    
    Param(
        # service type, accepted values are admin, user, report or core
        [Parameter(Mandatory=$true)]
        [string]$type,

        # credentials to authenticat against the web service
        [Parameter(Mandatory=$true)]
        [PSCredential]$credentials,

        [Parameter(Mandatory=$true)]
        [string]$uri
    )

    switch ($type)
    {
        'admin' {$service = "MbamAdministrationService/AdministrationService.svc"}
        'user' {$service = "MbamUserSupportService/UserSupportService.svc"}
        'report' {$service = "MbamComplianceStatusService/StatusReportingService.svc"}
        'core' {$service = "MbamRecoveryAndHardwareService/CoreService.svc"}
        Default {$service = "MbamAdministrationService/AdministrationService"}
    }

    try
    {
        $R = Invoke-WebRequest -URI "https://winsrv-Mbam.Mbam.local/$service" -Credential $credentials

        if ($R.StatusCode -eq "200")
        {
            Write-Output("Running") 
        }
        else 
        {
           Write-Output("Not running")
        }
    }
    catch
    {
        Write-Output("Unreachable")
        Write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error
    }  
}

function Get-MbamSQLServerServiceState
{
<#
.Synopsis
   Get the state of a SQLServer instance
.DESCRIPTION
   Get the state of a SQLServer instance
.EXAMPLE
   Get-SQLServerServiceStat MSSQL`$Mbam_SQLSERVER
.NOTES
    Normally a SQLServer service name is something like MSSQL$<yourinstancename>. So we have a $-sign in the name which has to be escaped in order to work correctly with powershell
#>
    [CmdletBinding()]
    Param
    (
        # The service name of the sqlserver instance, i.e. MSSQL$SQLSERVER
        [Parameter(Mandatory=$true)]
        $ServiceName
    )

    try {
        $status = Get-service | where name -eq $ServiceName -ErrorAction stop| select -ExpandProperty Status

        if ($status -ne $null)
        {
            # instance found, return status
            Write-Output($status)
        }
        else 
        {
            # no SQL-server instance with $serviceName found
            Write-Output("Not found")
        }
    }
    catch
    {
        Write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error
    }   
}

function Get-MbamFirewallPortState
{
<#
.Synopsis
   Get the firewall state of necessary port for Mbam.
.DESCRIPTION
   Get state of port 443 and if it allows inbound traffic to reach the webserver for Mbam HelpDesk and Administration
.OUTPUTS
    $true if port allows traffic
    $false if port blocks traffic or port allows traffic but rule is disabled
#>
   
    try
    {   
        # check firewall rule of port 443 (standard iis rule)
        $rule = Get-NetFirewallRule | where -property name -eq IIS-WebserverRole-HTTPS-In-TCP 
        
        if($rule -ne $null)
        {    
            # rule exists, check status 
            if ($rule.Enabled -eq "true")
            {
                # rule enabeld and allows traffice
                if ($rule.Action -eq "Allow")
                {   
                    Write-Output($true)
                }
                # rule enabled and blocks traffic
                else
                {
                    Write-Output($false)
                }
            }
            else
            {
                # rule disabled
                Write-Output($true) 
            }  
        }
        else
        {
            # Standard IIS-Webserver rule for port 443 not found
            Write-Output($true)
        }
    }
    catch
    {
        Write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error
    }   
}

function Get-MbamServerVersion25 
{
<#
.Synopsis
   Gets Mbam-Server version
.DESCRIPTION
   Gets the version number of the installed Mbam-Server
.OUTPUTS
   System.Object.String A string with the actual MABM version number
#>   
    try 
    {
        $currentVersion = Get-item 'HKLM:\SOFTWARE\Microsoft\Mbam Server' -ErrorAction Stop | Get-ItemProperty | select -ExpandProperty "Installed"
        
        Write-Output($currentVersion)
    }
    catch 
    {
       Write-Error("No Mbam-Server version >= 2.5 found")
       Write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error
    }
}

function Get-MbamHostname
{
    try 
    {
        if(Get-Module Microsoft.MBAM)
        {
            Get-MbamWebApplication -AdministrationPortal | select -ExpandProperty HostName -ErrorAction Stop
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

function Get-UserLogins
{
    [CmdletBinding()]
    Param(
        [DateTime]$date = (Get-Date).AddDays(-1)
    )

    Get-WmiObject -class Win32_NetworkLoginProfile |select name, caption, @{Name="lastlogin"; Expression={$_.ConvertToDateTime($_.LastLogon)}} | where lastlogin -GT $date
}



# Client functions
#############################

function Get-MbamClientAgentVersion 
{
<#
.Synopsis
   Gets Mbam-Agent version
.DESCRIPTION
   Gets the Mbam-Agent version of a client
.OUTPUTS
   System.String The actual versionnumber of the installed Mbam-Agent version as string or zero if no client agent was found
.NOTES
   WinRM has to be activated on the remote machine to Get a version number of a remote client
#>
    try
    {
        Get-Item 'HKLM:SOFTWARE\Microsoft\Mbam' -ErrorAction Stop | Get-ItemProperty | select -ExpandProperty "AgentVersion"
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
   Get the protection status of the operating system hard disk drive
.DESCRIPTION
   Gets the protection status of the operating system hard disk drive. The mountpoint of this drive is assumed to be c:\
#>  

    try 
    {
        if (Get-Module BitLocker)
        {
            Get-BitLockerVolume -MountPoint "C:" | Select -ExpandProperty ProtectionStatus -ErrorAction Stop
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
.INPUTS
    An array of hard disk mounting points
.OUTPUTS
    One protection status per given mounting point entry
.EXAMPLE
    Get-DiskProtectionStatus ("C:","D:")
#>    

    [CmdletBinding()]
    [Parameter(Mandatory=$true)]
    param(
        [string[]]$mountPoints
    )


    try 
    {
        if (Get-Module BitLocker)
        {
            Get-BitLockerVolume -MountPoint $mountPoints | Select -ExpandProperty ProtectionStatus -ErrorAction Stop
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
        $result = Get-Item $path -ErrorAction Stop | Get-ItemProperty | select -ExpandProperty $PolicyKey

        if ($result -eq $null)
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


##############################################################################################
#                                                            
# Section with test case functions for Microsoft Bitlocker and Monitoring  
# =======================================================================  
# 
# All tests should return an object with following note propertys:
#
#  - Name (String) => the name of test case, i.e. a unique index
#  - Task (String) => which result is expected
#  - Status (String) => short despcription of test result, like "Passed" or a error description
#  - Passed (String) => not passed = false; passed = true; warning = warning
#                                                            
############################################################################################### 


<#
    General server side test
    ========================

#>

function Test-LocalAdmins
{
# TC-Mbam-0042
#-------------

<#
.Synopsis
    Tests if the members of the local admin group matches the list of members in the file.
.DESCRIPTION
    Tests if the members of the local admin group matches the list of members in the file.
.INPUTS
    A list of SamAccountNames of members which are assumed to be in the local admin group. Use new-LocalAdminsFile.ps1 in module directory to initally create a snapshot
    of local admin group.
.OUTPUTS
    PSCustomObject  
#>

    Param(
        [Parameter(Mandatory=$true)]
        [Alias('LocalAdminGroupMembers')]
        [string[]] $knownAdmins
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0042")
    $obj | Add-Member NoteProperty Task("Members in local admin group are correct")

    $admins = Get-LocalAdmins

    if (-not($admins -eq $null) -and -not($knownAdmins -eq $null))
    {
        $compare = Compare-Object -ReferenceObject $admins -DifferenceObject $knownAdmins

        $nl = [System.Environment]::NewLine

        foreach($member in $compare) 
        {  
            if ($member.SideIndicator -eq "<=")
            {
                $unexpected += $member.InputObject + $nl
                $unexpectedCounter++
            }
            elseif ($member.SideIndicator -eq "=>")
            {
                $missing += $member.InputObject + $nl
                $missingCounter++
            }
        }

        if ($missing -and $unexpected)    
        {
            $obj | Add-Member NoteProperty Status("Not listed members found ($unexpectedCounter): $nl $unexpected $nl Missing members($missingCounter): $nl $missing")
            $obj | Add-Member NoteProperty Passed("false")
            Write-LogFile -Path $LogPath -name $LogName -message "Local admins - not listed members found: $unexpected $nl Missing members: $missing" -Level Error
        }
        elseif ($unexpected) 
        {
            $obj | Add-Member NoteProperty Status("Not listed members found($unexpectedCounter): $nl $unexpected")
            $obj | Add-Member NoteProperty Passed("false") 
            Write-LogFile -Path $LogPath -name $LogName -message "Local admins - not listed members found: $unexpected" -Level Error   
        }
        elseif ($missing)
        {
            $obj | Add-Member NoteProperty Status("Missing members($missingCounter): $nl $missing")
            $obj | Add-Member NoteProperty Passed("warning")
            Write-LogFile -Path $LogPath -name $LogName -message "Local admins - missing members: $missing" -Level Warning
        }
        else 
        {
            $obj | Add-Member NoteProperty Status("All correct")
            $obj | Add-Member NoteProperty Passed("true")
        }
    }
    else
    {
        $obj | Add-Member NoteProperty Status("An error occured while checking.")
        $obj | Add-Member NoteProperty Passed("false")
        Write-LogFile -Path $LogPath -name $LogName -message "An error occured. Either local admins could not be received or file knownLocalAdmins.txt is empty/could not be read"
    }

    Write-Output $obj
}

function Test-SccmClientUpdates
{
# TC-Mbam-0043
#-------------

<#
.Synopsis
    Tests if deployed and applicable updates are installed.
.DESCRIPTION
     Tests if deployed and applicable updates are installed. If updates are available a warning is returned with a list of applicable updates in the status property of the object.
.OUTPUTS
    PSCustomObject  
#>

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0043")
    $obj | Add-Member NoteProperty Task("All applicable updates via SCCM are installed.")

    try 
    {
        $SCCMUpdates = Get-CimInstance -Namespace 'root\ccm\ClientSDK' -ClassName 'CCM_SoftwareUpdate' -ErrorAction Stop

        if ($SCCMUpdates -eq $null)
        {
            # No updates applicable
            $obj | Add-Member NoteProperty Status("No updates appliable")
            $obj | Add-Member NoteProperty Passed("true")
        }
        else
        {
            $nl = [System.Environment]::NewLine
            $index = 1

            foreach($update in $SCCMUpdates)
            {
                $status += ($index++).ToString() + ": " + ($update.Name).Substring(0, [System.Math]::Min(75, $update.Name.Length)) + "..."
                $status += $nl + "KB" + $update.ArticleID  + $nl + $nl
                                
            }

            # Updates applicable
            $obj | Add-Member NoteProperty Status("The following updates are applicable" + $nl + $status)
            $obj | Add-Member NoteProperty Passed("warning")

            # Also log applicable updates in logfile
            Write-LogFile -Path $LogPath -name $LogName -message $status -Level Warning
        }
    }
    catch
    {
        $obj | Add-Member NoteProperty Status("SCCM client not installed.")
        $obj | Add-Member NoteProperty Passed("true")
        Write-LogFile -Path $LogPath -name $LogName -message "CCM class not found. SCCM client not installed?" -Level Error
    }    

    Write-Output $obj
}

function Test-LastUserLogins
{
# TC-Mbam-0044
#-----------------

<#
.Synopsis
   Checks, if only 
.DESCRIPTION
   Checks, if only 
.OUTPUTS
   PSCustomObject
#>
    [CmdletBinding()]
    Param(
        [string[]]$acceptedUsers
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0044")
    $obj | Add-Member NoteProperty Task("Only expected logins within last 24h on machine")

    $logins = Get-UserLogins

    # Check, if we have any login
    if ($logins -ne $null)
    {
        # Compare logged in usernames with the amount of accepted users to get only the users who are not accepted
        $compare = Compare-Object -ReferenceObject $logins.caption -DifferenceObject $acceptedUsers

        $nl = [System.Environment]::NewLine

        foreach($user in $compare.InputObject)
        {
            foreach($login in $logins)
            {
                if ($user -eq $login.caption)
                {
                    $unexpected += $login.caption + " | " + $login.lastlogin + $nl
                    break
                }
            }
        }
    }

    if ($unexpected) 
    {
        $obj | Add-Member NoteProperty Status("Unexpected logins found: $nl $unexpected")
        $obj | Add-Member NoteProperty Passed("warning") 
        Write-LogFile -Path $LogPath -name $LogName -message "Unexpected logins found: $unexpected" -Level Warning   
    }
    else 
    {
        $obj | Add-Member NoteProperty Status("No unexpected logins found")
        $obj | Add-Member NoteProperty Passed("true")
    }

    Write-Output $obj
}

function Test-DefaultDCConnection
{
# TC-Mbam-0047
#-----------------

<#
.Synopsis
   Checks, 
.DESCRIPTION
   Checks, 
.OUTPUTS
   PSCustomObject
#>
    
    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0047")

    try
    {
        $dc = Get-ADDomainController | select -ExpandProperty Name
        $obj | Add-Member NoteProperty Task("Default Domain Controller $dc is reachable (Ping-Status)")

        $connects = Test-Connection (Get-ADDomainController | select -ExpandProperty IPv4Address) -ErrorAction SilentlyContinue

        if ($connects.count -eq 0)
        {
            $obj | Add-Member NoteProperty Status("Not reachable")
            $obj | Add-Member NoteProperty Passed("false") 
            Write-LogFile -Path $LogPath -name $LogName -message "Domain Controller $dc not reachable" -Level Error  
        }

        elseif ($connects.count -le 2)
        {
            $obj | Add-Member NoteProperty Status("Partial reachable (<=50%)")
            $obj | Add-Member NoteProperty Passed("warning")
            Write-LogFile -Path $LogPath -name $LogName -message "Domain Controller $dc partial reachable (<50%)" -Level Warning 
        }

        else
        {
            $obj | Add-Member NoteProperty Status("Reachable")
            $obj | Add-Member NoteProperty Passed("true")           
        }
    }

    catch 
    {
        $obj | Add-Member NoteProperty Task("Default Domain Controller is reachable (Ping-Status)")
        $obj | Add-Member NoteProperty Status("Not reachable")
        $obj | Add-Member NoteProperty Passed("false") 
        Write-LogFile -Path $LogPath -name $LogName -message "Default Domain Controller not reachable" -Level Error  
    }

    Write-Output $obj
}

function Test-ForestDCsConnection
{
# TC-Mbam-0048
#-----------------

<#
.Synopsis
   Checks, 
.DESCRIPTION
   Checks, 
.OUTPUTS
   PSCustomObject
#>
    try
    {
        # get default domain controller
        $defaultDC = Get-ADDomainController | select -ExpandProperty IPv4Address
    }
    catch
    {

    }
    try
    {
        # get all domain controller in forest except for default domain controller
        $allDCs = (Get-ADForest).Domains | %{ Get-ADDomainController -Filter * -server $_} | where {$_.IPv4Address -NE $defaultDC}
        
        $i = 1

        # test connection to each dc
        foreach($dc in $allDCs)
        {
            $obj = New-Object PSObject
            $obj | Add-Member NoteProperty Name("TC-Mbam-0048.$i")
            $obj | Add-Member NoteProperty Task("Domain Controller "+$dc.Name+"("+$dc.IPv4Address+") is reachable (Ping-Status)")

            if (Test-Connection $dc.IPv4Address -ErrorAction SilentlyContinue -Quiet)
            {
                $obj | Add-Member NoteProperty Status("Reachable")
                $obj | Add-Member NoteProperty Passed("true")
            }

            else
            {
                $obj | Add-Member NoteProperty Status("Not reachable")
                $obj | Add-Member NoteProperty Passed("false") 
                Write-LogFile -Path $LogPath -name $LogName -message "Domain Controller $dc not reachable" -Level Error  
            }

            Write-Output $obj
        }
    }
    # domain controllers / forest not reachable
    catch
    {
        $obj = New-Object PSObject
        $obj | Add-Member NoteProperty Name("TC-Mbam-0048")
        $obj | Add-Member NoteProperty Task("Domain Controller is reachable (Ping-Status)")
        $obj | Add-Member NoteProperty Status("Not reachable")
        $obj | Add-Member NoteProperty Passed("false") 
        Write-Output $obj
        
        Write-LogFile -Path $LogPath -name $LogName -message "Domain Controllers in Forest not reachable" -Level Error  
    }
}

function Test-DNSServerConnection
{
# TC-Mbam-0046
#-----------------

<#
.Synopsis
   Checks, 
.DESCRIPTION
   Checks, 
.OUTPUTS
   PSCustomObject
#>
    $serverIPs = Get-DnsClientServerAddress | select -ExpandProperty ServerAddresses -Unique
    $counter = 1

    foreach($ip in $serverIPs)
    {
        $obj = New-Object PSObject
        $obj | Add-Member NoteProperty Name("TC-Mbam-0046.$counter")
        $obj | Add-Member NoteProperty Task("DNS-Server with IP $ip is reachable (Ping-Status)")

        if (Test-Connection $ip -ErrorAction SilentlyContinue -Quiet) 
        {
            $obj | Add-Member NoteProperty Status("Reachable")
            $obj | Add-Member NoteProperty Passed("true") 
        }
        else 
        {
            $obj | Add-Member NoteProperty Status("Not reachable")
            $obj | Add-Member NoteProperty Passed("false")
            Write-LogFile -Path $LogPath -name $LogName -message "DNS-server with IP $ip not reachable " -Level Error   
        }

        Write-Output $obj

        $counter++
    }
}

function Test-MaintenanceModeOn
{
# TC-Mbam-0034
#-----------------

<#
.Synopsis
   Checks, if maintenance mode is on for server.
.DESCRIPTION
   Checks, if maintenance mode is on for server.
.PARAMETERS
    System.String $pathToLogFile Filepath to the MMTool log file
.OUTPUTS
   PSCustomObject
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$pathToLogFile
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0034")
    $obj | Add-Member NoteProperty Task("Maintenance mode for server is off")


    if ((Get-MaintenanceMode $pathToLogFile) -eq $false)
    {
        $obj | Add-Member NoteProperty Status("Maintenance mode OFF")
        $obj | Add-Member NoteProperty Passed("true") 
        
    }
    else 
    {
        $obj | Add-Member NoteProperty Status("Maintenance mode ON")
        $obj | Add-Member NoteProperty Passed("warning")
        Write-LogFile -Path $LogPath -name $LogName -message "Maintenance mode ON" -Level Warning   
    }

    Write-Output $obj
}


<#
    MBAM specific server test
    =========================

#>

function Test-MbamComplianceDbConnectState
{
# TC-Mbam-0001
#-------------

<#
.Synopsis
   Tests wether the administration-website application was found and successfully connected to the compliance database
.DESCRIPTION
   Tests wether the administration-website application was found and successfully connected to the compliance database.
   Therefore the last system startup is determined and afterwards the event log of Mbam-web/operational is checked for an event with ID 200 that contains the expression "Compliance database" in the message.
   Until the website is not access since the last system reboot, no event log records will be created and therefore the function will return a PSCustomObject with status "not found".
.OUTPUTS
 PSCustomObject
.EXAMPLE
   Test-ComplianceDBConnectState

   Name            Task                                                    Status          Passed
   ----            ----                                                    ------          ------
   TC-Mbam-0001    Administration-website application found and success... Connected       True
   
#>

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0001")
    $obj | Add-Member NoteProperty Task("Administration-website application found and successfully connected to compliance database")
        
    $lastStartup = Get-SystemStartupTime

    try
    {
        # In case the HelpDesk webpage was not called since the last system startup, we trigger a simple call to it, but without a output.
        # After that the event we will be looking for in the event log should be created, otherwise there is something wrong
        Test-MbamHelpDeskPage | Out-Null

        $connected = Get-WinEvent -FilterHashtable @{logname="microsoft-windows-Mbam-web/operational";StartTime=$lastStartup;} -ErrorAction Stop | where {$_.Message -Like "*Compliance database*" -and $_.ID -eq 200} 

        if ($connected -ne $null)
        {
            # Event was found and connection to database was once established
            $obj | Add-Member NoteProperty Status("Connected")
            $obj | Add-Member NoteProperty Passed("true")
        }
        else 
        {
            # Event still not found, something could be wrong.
            $obj | Add-Member NoteProperty Status("Not connected")
            $obj | Add-Member NoteProperty Passed("false")
        }
    }
    catch 
    {
        $obj | Add-Member NoteProperty Status("Not found")
        $obj | Add-Member NoteProperty Passed("false")
        Write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error
    }

    Write-Output $obj

}

function Test-MbamRecoveryDbConnectState
{

# TC-Mbam-0002
#-------------

<#
.Synopsis
    Tests wether the administration-website application was found and successfully connected to the recovery database
.DESCRIPTION
    Tests wether the administration-website application was found and successfully connected to the recovery database.
    Therefore the last system startup is determined and afterwards the event log of Mbam-web/operational is checked for an event with ID 200 that contains the expression "Recovery database" in the message.
    Until the website is not access since the last system reboot, no event log record will be created and therefore the function will return a PSCustomObject with status "not found".
.OUTPUTS
    PSCustomObject
.EXAMPLE
    Test-RecoveryDBConnectState
   
    Name            Task                                                    Status          Passed
    ----            ----                                                    ------          ------
    TC-Mbam-0002    Administration-website application found and success... Connected       True
#>

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0002")
    $obj | Add-Member NoteProperty Task("Administration-website application found and successfully connected to recovery database")
        
    $lastStartup = Get-SystemStartupTime

    try 
    {
        # In case the HelpDesk webpage was not called since the last system startup, we trigger a simple call to it, but without a output.
        # After that the event we will be looking for in the event log should be created, otherwise there is something wrong
        Test-MbamHelpDeskPage | Out-Null

        $connected = Get-WinEvent -FilterHashtable @{logname="microsoft-windows-Mbam-web/operational";StartTime=$lastStartup;} -ErrorAction Stop | where {$_.Message -Like "*Recovery database*" -and $_.ID -eq 200}

        if ($connected -ne $null)
        {  
            # Event was found and connection to database was once established
            $obj | Add-Member NoteProperty Status("Connected")
            $obj | Add-Member NoteProperty Passed("true")
        }
        else 
        {
            # Event still not found, something could be wrong.
            $obj | Add-Member NoteProperty Status("Not connected")
            $obj | Add-Member NoteProperty Passed("false")
        }
    }
    catch
    {
        $obj | Add-Member NoteProperty Status("Not found")
        $obj | Add-Member NoteProperty Passed("false")
        Write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error 
    }

    Write-Output $obj    
}

function Test-MbamHelpDeskSPNState
{
# TC-Mbam-0004
#-------------

<#
.Synopsis
    Tests if the HelpDesk has its Service Principal Name registered successfully.
.DESCRIPTION
    Tests if the HelpDesk has its Service Principal Name registered successfully. Therefore the event log is checked for a record with ID 202 and message containing the phrase "HelpDesk" 
    which was created after last system startup. If the HelpDesk website is not access since last startup, no record is created and the function will return "Not registered" 
.OUTPUTS
    PSCustomObject
#>  

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0004")
    $obj | Add-Member NoteProperty Task("HelpDesk has its Service Principal Name registered successfully")

    $lastStartup = Get-SystemStartupTime

    try
    {
        $SPNregistered = Get-WinEvent -FilterHashtable @{logname="microsoft-windows-Mbam-web/operational";StartTime=$lastStartup;} -ErrorAction stop | where {$_.Message -Like "*HelpDesk*" -and $_.ID -eq 202}

        # Set status, if no log record was found, an ObjectNotFound exception is thrown
        $obj | Add-Member NoteProperty Status("Registered")
        $obj | Add-Member NoteProperty Passed("true")
    }
    catch
    {
        # No registration logged since last startup
        $obj | Add-Member NoteProperty Status("Not found")
        $obj | Add-Member NoteProperty Passed("false")
        Write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error
    }

    Write-Output $obj
    
}

function Test-MbamSelfServiceSPNState
{
# TC-Mbam-0005
#-------------

<#
.Synopsis
    Tests if the SelfService Portal has its Service Principal Name registered successfully.
.DESCRIPTION
    Tests if the SelfService Portal has its Service Principal Name registered successfully. Therefore the event log is checked for a record with ID 202 and message containing the phrase "SelfService" 
    which was created after last system startup. If the HelpDesk website is not access since last startup, no record is created and the function will return a PSCustomObject with status "Not found". 
.OUTPUTS
    PSCustomObject
#>   

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0005")
    $obj | Add-Member NoteProperty Task("SelfService Portal has its Service Principal Name registered successfully")

    $lastStartup = Get-SystemStartupTime

    try
    {
        $SPNregistered = Get-WinEvent -FilterHashtable @{logname="microsoft-windows-Mbam-web/operational";StartTime=$lastStartup;} -ErrorAction stop | where {$_.Message -Like "*SelfService*" -and $_.ID -eq 202}

        # Set status, if no log record was found, an ObjectNotFound exception is thrown
        $obj | Add-Member NoteProperty Status("Registered")
        $obj | Add-Member NoteProperty Passed("true")
            
    }
    catch
    {
        # No registration logged since last startup
        $obj | Add-Member NoteProperty Status("Not found")
        $obj | Add-Member NoteProperty Passed("false")
        Write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error
    }

    Write-Output $obj

}

function Test-MbamWCFServiceState
{
# TC-Mbam-0006
#-------------

<#
.Synopsis
    Tests the state of a WCF-service for Mbam.
.DESCRIPTION
    Tests the state of a Windows Communication Foundation service for Mbam. The following service types are possible
    admin:  for the administration service
    user:   for the user support service
    report: for the status report service
    core:   for the core service   
.OUTPUTS 
    PSCustomObject
.EXAMPLE
    Test-MbamWCFServiceState -type admin -credentials domain\username
#>
    Param(
        # service type, accepted values are admin, user, report or core
        [Parameter(Mandatory=$true)]
        [string]$type,

        # credentials to authenticat against the web service
        [Parameter(Mandatory=$true)]
        [PSCredential]$credentials,

        [Parameter(Mandatory=$true)]
        [string]$uri
    )

    Switch ($type)
    {
        'admin' {$service = "MbamAdministrationService/AdministrationService.svc"}
        'user' {$service = "MbamUserSupportService/UserSupportService.svc"}
        'report' {$service = "MbamComplianceStatusService/StatusReportingService.svc"}
        'core' {$service = "MbamRecoveryAndHardwareService/CoreService.svc"}
        Default {$service = "MbamAdministrationService/AdministrationService"}
    }

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0006")
    $obj | Add-Member NoteProperty Task("WCF service '$service' state:")

    Try
    {
        $R = Invoke-WebRequest -URI "$uri/$service" -Credential $credentials

        if ($R.StatusCode -eq "200")
        {
            $obj | Add-Member NoteProperty Status("Running")
            $obj | Add-Member NoteProperty Passed("true")
        }
        else 
        {
            $obj | Add-Member NoteProperty Status("Not running")
            $obj | Add-Member NoteProperty Passed("false")
        }
    }
    Catch
    {
        $obj | Add-Member NoteProperty Status("Unreachable")
        $obj | Add-Member NoteProperty Passed("false")
        Write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error
    }

    Write-Output $obj
    
}

function Test-MbamSQLServerServiceState
{
<#
.Synopsis
   Tests the state of a SQLServer instance
.DESCRIPTION
   Tests the state of a SQLServer instance
.EXAMPLE
   Test-SQLServerServiceStat MSSQL`$Mbam_SQLSERVER
   Running
.NOTES
    Normally a SQLServer service name is something like MSSQL$<yourinstancename>. So we have a $-sign in the name which has to be escaped in order to work correctly with powershell
#>
    [CmdletBinding()]
    Param
    (
        # The service name of the sqlserver instance, i.e. MSSQL$SQLSERVER
        [Parameter(Mandatory=$true)]
        $ServiceName
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0012")
    $obj | Add-Member NoteProperty Task("State of a SQLServer instance: $ServiceName")

    try
    {
        $status = Get-service | where name -eq $ServiceName -ErrorAction stop| select -ExpandProperty Status

        if ($status -ne $null)
        {
            # instance found, set status
            $obj | Add-Member NoteProperty Status($status)

            # SQL-server is up and runnning
            if ($status -eq "running")
            {
                $obj | Add-Member NoteProperty Passed("true") 
            }
            # SQL-server is paused or stopped
            else
            {     
                $obj | Add-Member NoteProperty Passed("false")
            }
        }
        else 
        {
            # no SQL-server instance with $serviceName found
            $obj | Add-Member NoteProperty Status("Not found")
            $obj | Add-Member NoteProperty Passed("false")
        }
    }
    catch
    {
        # no SQL-server instance with $serviceName found
        $obj | Add-Member NoteProperty Status("Not found")
        $obj | Add-Member NoteProperty Passed("false")
        Write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error
    }

    Write-Output $obj
}

function Test-MbamComplianceDbServerConnection                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     
{
# TC-Mbam-0013.1
#---------------  

    try 
    {
        if(get-Module Microsoft.MBAM)
        {
            $connectionString = Get-MbamWebApplication -AdministrationPortal | select -ExpandProperty ComplianceAndAuditDBConnectionString
        }
        else
        {
            # log error
            $msg = "PowerShell module Microsoft.MBAM not found"
            write-LogFile -Path $LogPath -name $LogName -message $msg -Level Warning
        }

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

        $obj = Test-MbamSQLServerConnection $destination
    }
    catch
    {
        $obj = New-Object PSObject
        $obj | Add-Member NoteProperty Status("Could not retrieve FQDN of SQL-Server")
        $obj | Add-Member NoteProperty Passed("false")

        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }

    $obj | Add-Member NoteProperty Name("TC-Mbam-0013.1")
    $obj | Add-Member NoteProperty Task("Mbam Compliance Database Server $destination is reachable")

    Write-Output $obj
}

function Test-MbamRecoveryDbServerConnection
{
# TC-Mbam-0013.2
#---------------  

    try
    {
        if(Get-Module Microsoft.MBAM)
        {
            $connectionString = Get-MbamWebApplication -AdministrationPortal | select -ExpandProperty RecoveryDBConnectionString
        }
        else
        {
            # log error
            $msg = "PowerShell module Microsoft.MBAM not found"
            write-LogFile -Path $LogPath -name $LogName -message $msg -Level Warning
        }

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

        $obj = Test-MbamSQLServerConnection $destination
    }
    catch
    {
        $obj = New-Object PSObject
        $obj | Add-Member NoteProperty Status("Could not retrieve FQDN of SQL-Server")
        $obj | Add-Member NoteProperty Passed("false")

        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }

    $obj | Add-Member NoteProperty Name("TC-Mbam-0013.2")
    $obj | Add-Member NoteProperty Task("Mbam Recovery Database Server $destination is reachable")

    Write-Output $obj
}

function Test-MbamHelpDeskPage
{
# TC-Mbam-0015

<#
.Synopsis
   Checks, if the HelpDesk page is reachable
.DESCRIPTION
   Checks, if the HelpDesk page is reachable. At this time it only checks https connections. 
.OUTPUTS
    PSCustomObject
#>
    [CmdletBinding()]
    Param(
        # Check with SSL connection
        [switch]$https
    )    

    $server = Get-MbamHostname
    if(Get-Module Microsoft.MBAM)
    {
        $helpdesk = Get-MbamWebApplication -AdministrationPortal | select -ExpandProperty VirtualDirectory 
    }
    else
    {
            # log error
            $msg = "PowerShell module Microsoft.MBAM not found"
            write-LogFile -Path $LogPath -name $LogName -message $msg -Level Warning
        }
    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0015")
    $obj | Add-Member NoteProperty Task("HelpDesk page $server$helpdesk is reachable")   
  
    $protocol = @{$true = "https://"; $false = "http://"}[$https -eq $true] 

    Try 
    {
           # this webrequest should fail because it makes a request without credentials, but if we Get a 401, the page is running
           Invoke-WebRequest -URI ($protocol+$server+$helpdesk)
        }
    Catch [System.Net.WebException]
    {
            # let's check if we are not authorized, which in this case is good because the page seems to be running
            if ($_.ErrorDetails.Message -like "*401.2 - Unauthorized*")
            {
                $obj | Add-Member NoteProperty Status("Reachable")
                $obj | Add-Member NoteProperty Passed("true")
            }
            else
            {
                $obj | Add-Member NoteProperty Status("Not reachable")
                $obj | Add-Member NoteProperty Passed("false")
            }
           
        }
    Catch
    {
            $obj | Add-Member NoteProperty Status("Not reachable")
            $obj | Add-Member NoteProperty Passed("false")
            Write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error
        }

    Write-Output $obj
    
}

function Test-MbamSelfServicePage
{
# TC-Mbam-0016

<#
.Synopsis
   Checks, if the HelpDesk page is reachable
.DESCRIPTION
   Checks, if the HelpDesk page is reachable. At this time it only checks https connections. 
.OUTPUTS
    PSCustomObject
#>
    [CmdletBinding()]
    Param(
        # Check with SSL connection
        [switch]$https
    )
    
    
    $server = Get-MbamHostname

    if(Get-Module Microsoft.MBAM)
    {
        $selfservice = Get-MbamWebApplication -SelfServicePortal | select -ExpandProperty VirtualDirectory 
    }
    else
    {
        # log error
        $msg = "PowerShell module Microsoft.MBAM not found"
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Warning 
    }

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0016")
    $obj | Add-Member NoteProperty Task("SelfService page $server$selfservice is reachable")

   
    $protocol = @{$true = "https://"; $false = "http://"}[$https -eq $true]  

    try 
    {
        # this webrequest should fail because it makes a request without credentials, but if we get a 401, the page is running
        Invoke-WebRequest -URI ($protocol+$server+$selfservice)
    }
    catch [System.Net.WebException]
    {
        # let's check if we are not authorized, which in this case is good because the page seems to be running
        if ($_.ErrorDetails.Message -like "*401.2 - Unauthorized*")
        {
            $obj | Add-Member NoteProperty Status("Reachable")
            $obj | Add-Member NoteProperty Passed("true")
        }
        else
        {
            $obj | Add-Member NoteProperty Status("Not reachable")
            $obj | Add-Member NoteProperty Passed("false")
        }
           
    }
    catch
    {
        $obj | Add-Member NoteProperty Status("Not reachable")
        $obj | Add-Member NoteProperty Passed("false")
        Write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error
    }

    Write-Output $obj
}

function Test-MbamFirewallPortState
{
# TC-Mbam-0017

<#
.Synopsis
   Tests the firewall for IIS rule on port 443 for Mbam.
.DESCRIPTION
   Tests, if port 443 allows inbound traffic to reach the webserver for Mbam HelpDesk and Administration
.OUTPUTS
    $true if port allows traffic
    $false if port blocks traffic, port allows traffic but rule is disabled or rule is not found
#>
        
    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0017")
    $obj | Add-Member NoteProperty Task("Port 443 allows inbound traffic to reach the webserver for Mbam HelpDesk and Administration")

    try
    {
        # check firewall rule of port 443 (standard iis rule)
        $rule = Get-NetFirewallRule | where -property name -eq IIS-WebserverRole-HTTPS-In-TCP 
        
        if($rule -ne $null)
        {     
            if ($rule.Enabled -eq "true")
            {
                if ($rule.Action -eq "Allow")
                {
                    $obj | Add-Member NoteProperty Status("Enabled, Allow")
                    $obj | Add-Member NoteProperty Passed("true")
                }
                else
                {
                    $obj | Add-Member NoteProperty Status("Enabled, Block")
                    $obj | Add-Member NoteProperty Passed("false")
                }
            }
            else
            {
                $obj | Add-Member NoteProperty Status("Disabled")
                $obj | Add-Member NoteProperty Passed("true") 
            }  
        }
        else
        {
            # Standard IIS-Webserver rule for port 443 not found
            $obj | Add-Member NoteProperty Status("Not found")
            $obj | Add-Member NoteProperty Passed("true")
        }
    }
    catch
    {
        $obj | Add-Member NoteProperty Status("An error occured, see log file for more info!")
        $obj | Add-Member NoteProperty Passed("false")
        Write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error
    }

    Write-Output $obj
}

function Test-MbamWebServerRoleState 
{
# TC-Mbam-0018
#-------------

<#
.Synopsis
   Checks, if webserver role is installed
.DESCRIPTION
   Checks, if webserver role is installed
.OUTPUTS
    PSCustomObject
#>   

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0018")

    $f = Get-WindowsFeature Web-Server 

    $obj | Add-Member NoteProperty Task("Windows Webserver role")
    $obj | Add-Member NoteProperty Status($f.InstallState.ToString())
    if ($f.Installed)
    {
        $obj | Add-Member NoteProperty Passed("true")
    }
    elseif (-not $f.Installed)
    {
        $obj | Add-Member NoteProperty Passed("false")
    }
    else 
    {
        $obj | Add-Member NoteProperty Passed("warning")
    }

    Write-Output $obj
}

function Test-MbamWebserverFeatureState 
{
# TC-Mbam-0019
#-------------

<#
.Synopsis
   Checks, if all necessary webserver features for Mbam are installed
.DESCRIPTION
   Checks, if all necessary webserver features for Mbam are installed
.OUTPUTs
    PSCustomObject
.EXAMPLE
    Test-MbamWebserverFeatureState 
    Name             Task                                                       Status          Passed
    ----             ----                                                       ------          ------
    TC-Mbam-0019.1   Windows Feature: Statischer Inhalt (Web-Static-Content)    Installed       True
    TC-Mbam-0019.2   Windows Feature: Standarddokument (Web-Default-Doc)        Installed       True
    TC-Mbam-0019.3   Windows Feature: ASP.NET 4.5 (Web-Asp-Net45)               Installed       True
    ...
#>   
    [CmdletBinding()]
    param(
        $featureList = @(
            'Web-Static-Content', 
            'Web-Default-Doc',
            'Web-Asp-Net45', 
            'Web-Net-Ext45', 
            'Web-ISAPI-Ext', 
            'Web-ISAPI-Filter', 
            'Web-Windows-Auth', 
            'Web-Filtering')
    )
    
    $i = 1

    foreach($feature in $featureList)
    {
        $f = Get-WindowsFeature $feature

        $obj = New-Object PSObject
        $obj | Add-Member NoteProperty Name("TC-Mbam-0019.$i")
        $name = $f.DisplayName
        $obj | Add-Member NoteProperty Task("Windows Feature: $name ($feature)")
        $obj | Add-Member NoteProperty Status($f.InstallState.ToString())
        if ($f.Installed)
        {
            $obj | Add-Member NoteProperty Passed("true")
        }
        elseif (-not $f.Installed)
        {
            $obj | Add-Member NoteProperty Passed("false")
        }
        else 
        {
            $obj | Add-Member NoteProperty Passed("warning")
        }

        Write-Output $obj
        $i++
    }
}

function Test-MbamWebserverServiceState
{
# TC-Mbam-0020
#-------------

<#
.Synopsis
   Checks, if the web server services are running
.DESCRIPTION
   Checks, if the web server services are running
.OUTPUTs
   PSCustomObject
#>
    [CmdletBinding()]
    param(
        $serviceList = @(
            'WAS', 
            'W3SVC')
    )


    $i = 1

    foreach($service in $serviceList)
    {
        $s = Get-service | where name -eq $service

        $obj = New-Object PSObject
        $obj | Add-Member NoteProperty Name("TC-Mbam-0020.$i")
        $name = $s.DisplayName
        $obj | Add-Member NoteProperty Task("Webserver service: $name ($service)")

        if($s -ne $null)
        {
            # service found, add status 
            $obj | Add-Member NoteProperty Status(($s.Status).ToString())

            if ($s.Status -eq "running")
            {
                $obj | Add-Member NoteProperty Passed("true")
            }
            else 
            {
                # service paused or stopped
                $obj | Add-Member NoteProperty Passed("warning")
            }
            }
            else 
            {
            # service not found
            $obj | Add-Member NoteProperty Status("Not found")
            $obj | Add-Member NoteProperty Passed("false")

            }

        Write-Output $obj
        $i++
    }
}

function Test-MbamWindowsFeatureState 
{
# TC-Mbam-0021
#-------------

<#
.Synopsis
   Checks, if all necessary windows features for Mbam are installed
.DESCRIPTION
   Checks, if all necessary windows features for Mbam are installed
.OUTPUTs
    PSCustomObject
.EXAMPLE
    Test-MbamWindowsFeatureState 
    Name             Task                                                      Status       Passed
    ----             ----                                                      ------       ------
    TC-Mbam-0021.1   Windows Feature: .NET Framework 4.5 (Net-Framework-4...   Installed    True
    TC-Mbam-0021.2   Windows Feature: HTTP-Aktivierung (NET-WCF-HTTP-Acti...   Installed    True
    ...
#>   
    [CmdletBinding()]
    param(
        $featureList = @(
            'Net-Framework-45-Core', 
            'NET-WCF-HTTP-Activation45', 
            'NET-WCF-TCP-Activation45', 
            'WAS-Process-Model', 
            'WAS-NET-Environment', 
            'WAS-Config-APIs')
    )
    
        $i = 1

    foreach($feature in $featureList)
    {
        $f = Get-WindowsFeature $feature

        $obj = New-Object PSObject
        $obj | Add-Member NoteProperty Name("TC-Mbam-0021.$i")
        $name = $f.DisplayName
        $obj | Add-Member NoteProperty Task("Windows Feature: $name ($feature)")
        $obj | Add-Member NoteProperty Status($f.InstallState.ToString())
        if ($f.Installed)
        {
            $obj | Add-Member NoteProperty Passed("true")
        }
        elseif (-not $f.Installed)
        {
            $obj | Add-Member NoteProperty Passed("false")
        }
        else 
        {
            $obj | Add-Member NoteProperty Passed("warning")
        }

        Write-Output $obj
        $i++
    }
}

function Test-MbamServerVersion25 
{ 
# TC-Mbam-0032
#-----------------

<#
.Synopsis
   Checks, if Mbam-Server version is correct
.DESCRIPTION
   Checks, if the version number of the installed Mbam-Server is like the passed version number 
.OUTPUTS
   PSCustomObject
#>  
    Param(
        # Version number
        [Parameter(Mandatory=$true)]
        [string]$version
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0032")
    $obj | Add-Member NoteProperty Task("Mbam-server version")

    try 
    {
        $currentVersion = Get-item 'HKLM:\SOFTWARE\Microsoft\Mbam Server' -ErrorAction Stop | Get-ItemProperty | select -ExpandProperty "Installed"
        
        if ($version -eq $currentVersion)
        {
            $obj | Add-Member NoteProperty Status("Version correct, installed version is $currentVersion")
            $obj | Add-Member NoteProperty Passed("true")
        }
        else
        {
            $obj | Add-Member NoteProperty Status("Versions differ, installed version is $currentVersion")
            $obj | Add-Member NoteProperty Passed("warning")
        }
    }
    catch 
    {
       $obj | Add-Member NoteProperty Status("No Mbam-Server Version >= 2.5 found")
       $obj | Add-Member NoteProperty Passed("false")
       write-LogFile -Path $LogPath -name $LogName -Message "Could not retrieve Mbam version. No registry entry for Mbam version >= 2.5 found"  -Level Error
    }

    Write-Output $obj
}

function Test-MbamSecurityGrpMembers 
{
# TC-Mbam-0035
#-----------------

<#
.Synopsis
   Checks, if only autherized members are in the security group
.DESCRIPTION
   Checks, if only autherized members are in the given security group
.OUTPUTS
   PSCustomObject
#>
    [CmdletBinding()]
    Param(
        # The Mbam security group to check
        [Parameter(Mandatory=$true)]
        [ValidateSet(“AdvHelpDesk”,”HelpDesk”,”ReportsRO”)] 
        [string]$group,

        # Members that should be in the security group
        [Parameter(Mandatory=$true)]
        [string[]]$members  
    )

    if(Get-Module Microsoft.MBAM)
    {
        switch($group)
        {
            "AdvHelpDesk" { $groupname = Get-MbamWebApplication -AdministrationPortal | select -ExpandProperty AdvancedHelpdeskAccessGroup -ErrorAction Stop; $i = 1}
    
            "HelpDesk" { $groupname = Get-MbamWebApplication -AdministrationPortal | select -ExpandProperty HelpdeskAccessGroup -ErrorAction Stop; $i = 2}

            "ReportsRO" { $groupname = Get-MbamWebApplication -AdministrationPortal | select -ExpandProperty ReportsReadOnlyAccessGroup -ErrorAction Stop; $i = 3}
        }
    }
    else
    {
        # log error
        $msg = "PowerShell module Microsoft.MBAM not found"
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Warning
        return
    }

    $groupname = $groupname.Remove(0, $groupname.IndexOf('\')+1)
    
    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0035.$i")
    $obj | Add-Member NoteProperty Task("Security group members in Group $groupname are correct")

    try 
    {
        
        if(Get-Module ActiveDirectory)
        {
            $admins = Get-ADGroupMember $groupname -Recursive | select -ExpandProperty SamAccountName
        }
        else
        {
            # log error
            $msg = "PowerShell module ActiveDirectory not found"
            write-LogFile -Path $LogPath -name $LogName -message $msg -Level Warning
            return
        }

        $nl = [System.Environment]::NewLine

        $compare = Compare-Object -ReferenceObject $admins -DifferenceObject $members -ErrorAction Stop
        $unexpectedCounter, $missingCounter = 0, 0


        foreach($member in $compare) 
        {  
            if ($member.SideIndicator -eq "<=")
            {
                $unexpected += $member.InputObject + $nl
                $unexpectedCounter++
            }
            elseif ($member.SideIndicator -eq "=>")
            {
                $missing += $member.InputObject + $nl
                $missingCounter++
            }
        }

        if ($missing -and $unexpected)    
        {
            $obj | Add-Member NoteProperty Status("Not listed members found ($unexpectedCounter): $nl $unexpected $nl Missing members ($missingCounter): $nl $missing")
            $obj | Add-Member NoteProperty Passed("false")
            Write-LogFile -Path $LogPath -name $LogName -message "Not listed members found ($unexpectedCounter): $nl $unexpected $nl Missing members ($missingCounter): $nl $missing" -Level Error
        }
        elseif ($unexpected) 
        {
            $obj | Add-Member NoteProperty Status("Not listed members found ($unexpectedCounter): $nl $unexpected")
            $obj | Add-Member NoteProperty Passed("false") 
            Write-LogFile -Path $LogPath -name $LogName -message "Not listed members found ($unexpectedCounter): $unexpected" -Level Error   
        }
        elseif ($missing)
        {
            $obj | Add-Member NoteProperty Status("Missing members ($missingCounter): $nl $missing")
            $obj | Add-Member NoteProperty Passed("warning")
            Write-LogFile -Path $LogPath -name $LogName -message "Missing members ($missingCounter): $missing" -Level Warning
        }
        else 
        {
            $obj | Add-Member NoteProperty Status("All correct")
            $obj | Add-Member NoteProperty Passed("true")
        }
    }
    catch
    {
        $obj | Add-Member NoteProperty Status("An error occured while checking.")
        $obj | Add-Member NoteProperty Passed("false")
        Write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error
    }

    Write-Output $obj
}

function Test-MbamSSLCertificateExpirationDate
{
# TC-Mbam-0039
#-----------------

<#
.Synopsis
   Checks, if the certificate of the Mbam Webserver is valid.
.DESCRIPTION
   Checks, if the certificate of the Mbam Webserver is valid.
.OUTPUTS
   PSCustomObject
#>

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0039")
    $obj | Add-Member NoteProperty Task("Certificate expiration date not reached")

    try 
    {
        $host = Get-MbamHostname

        $binding = Get-WebBinding -HostHeader $host

        $certObj = get-item ("cert:\LocalMachine\"+$binding.certificateStoreName+"\"+$binding.certificateHash) | select *

        $days = ($certObj.NotAfter.Date - (Get-Date).Date).Days
       
        if (($days -le $ConfigFile.Settings.CertificateExpiresWarning) -and ($days -ge 0))
        {
            $obj | Add-Member NoteProperty Status("Certificate expires in $days days")
            $obj | Add-Member NoteProperty Passed("false")
        }
        elseif ($days -lt 0)
        {
            $obj | Add-Member NoteProperty Status("Certificate expired")
            $obj | Add-Member NoteProperty Passed("false")
        }
        else 
        {
            $obj | Add-Member NoteProperty Status("Certificate not expired")
            $obj | Add-Member NoteProperty Passed("true")
        }
    }
    catch
    {
        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }

    Write-Output $obj
}

function Test-MbamHelpDeskSslOnly
{
# TC-Mbam-0011
#-----------------

<#
.Synopsis
   Checks, if the Mbam webpages for HelpDesk is only reachable on https.
.DESCRIPTION
   Checks, if the Mbam webpages for HelpDesk is only reachable on https.
.OUTPUTS
   PSCustomObject
#>

    $server = Get-MbamHostname
    $helpdesk = Get-MbamWebApplication -AdministrationPortal | select -ExpandProperty VirtualDirectory  

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0011")
    $obj | Add-Member NoteProperty Task("HelpDesk page $server$helpdesk is only reachable over SSL connection") 

    $https = Test-MbamHelpDeskPage -https
    $http = Test-MbamHelpDeskPage   

    if (($https.Passed -eq "true") -and ($http.Passed -eq "false"))
    {
        $obj | Add-Member NoteProperty Status("Only reachable over https")
        $obj | Add-Member NoteProperty Passed("true")
    }
    elseif (($https.Passed -eq "true") -and ($http.Passed -eq "true"))
    {
        $obj | Add-Member NoteProperty Status("Reachable over https and http")
        $obj | Add-Member NoteProperty Passed("warning")
    }
    else
    {
        $obj | Add-Member NoteProperty Status("Not reachable at all")
        $obj | Add-Member NoteProperty Passed("false")
    }
        
    Write-Output $obj
}

function Test-MbamSelfServiceSslOnly
{
# TC-Mbam-0012
#-----------------

<#
.Synopsis
   Checks, if the Mbam webpages for SelfService is only reachable on https.
.DESCRIPTION
   Checks, if the Mbam webpages for SelfService is only reachable on https.
.OUTPUTS
   PSCustomObject
#>

    $server = Get-MbamHostname
    $selfservice = Get-MbamWebApplication -SelfServicePortal | select -ExpandProperty VirtualDirectory  

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0012")
    $obj | Add-Member NoteProperty Task("SelfService page $server$selfservice is only reachable over SSL connection") 

    $https = Test-MbamSelfServicePage -https
    $http = Test-MbamSelfServicePage
        

    if (($https.Passed -eq "true") -and ($http.Passed -eq "false"))
    {
        $obj | Add-Member NoteProperty Status("Only reachable over https")
        $obj | Add-Member NoteProperty Passed("true")
    }
    elseif (($https.Passed -eq "true") -and ($http.Passed -eq "true"))
    {
        $obj | Add-Member NoteProperty Status("Reachable over https and http")
        $obj | Add-Member NoteProperty Passed("warning")
    }
    else
    {
        $obj | Add-Member NoteProperty Status("Not reachable at all")
        $obj | Add-Member NoteProperty Passed("false")
    }
        
    Write-Output $obj
}

function Test-MbamCertificateThumbprint
{
# TC-Mbam-0010
#-----------------

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$thumbprint
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0010")
    $obj | Add-Member NoteProperty Task("Mbam certificate thumbprint is valid") 

    # get the actual thumbprint of MBAM
    $actualThumbprint = Get-MbamWebApplication -AdministrationPortal | select -ExpandProperty CertificateThumbprint

    # do the thumbprints match?
    if($actualThumbprint -eq $thumbprint)
    {
        $obj | Add-Member NoteProperty Status("Thumbprint is valid")
        $obj | Add-Member NoteProperty Passed("true")
    }
    else
    {
        $obj | Add-Member NoteProperty Status("Thumbprint is not valid")
        $obj | Add-Member NoteProperty Passed("false")
    }

    Write-Output $obj
}

function Test-MbamCertificateValidationState
{
# TC-Mbam-0033
#-------------

<#
.Synopsis
   Verifies that the certificate of the web page is valid.
.DESCRIPTION
   Verifies that the certificate of the web page is valid. 
   This is done by checking the revoke status of the certificate and if DNS name in certificate matches the Mbam hostname.
.OUTPUTS
   PSCustomObject
#>
    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0033")
    $obj | Add-Member NoteProperty Task("Mbam certificate is valid") 

    $location = Get-Location

    try 
    {
        # Get Mbam application object
        $mbamApp = Get-MbamWebApplication -AdministrationPortal

        # Get a certificate object of correspondingly thumbprint
        Set-Location Cert:\
        $certificate = dir -Recurse | where Thumbprint -EQ $mbamApp.CertificateThumbprint

        # Check validation of certificate
        if(Test-Certificate -DNSName $mbamApp.Hostname -cert $certificate -ErrorAction Stop)
        {
            $obj | Add-Member NoteProperty Status("Certificate is valid")
            $obj | Add-Member NoteProperty Passed("true")
        }
        else
        {
            $obj | Add-Member NoteProperty Status("Certificate not valid")
            $obj | Add-Member NoteProperty Passed("false")
        }

            
    }
    catch
    { 
        $obj | Add-Member NoteProperty Passed("false")

        # Create error message
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()

        # Check for specific error messages
        # Certificate is revoked 
        if($msg -like "*CRYPT_E_REVOKED*")
        {
            $obj | Add-Member NoteProperty Status("Certificate revoked")
        }
        # DNS name of certificate does not match the hostname
        elseif ($msg -like "*CERT_E_CN_NO_MATCH*")
        {
            $obj | Add-Member NoteProperty Status("CN-Name of certificate does not match")
        }
        # all other errors
        else
        {
            $obj | Add-Member NoteProperty Status("An error occurred, see logfile for more infos")
        }

        # log error
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }

    Set-Location $location
    Write-Output $obj
}

function Test-MbamServerRestartedAfterUpdate
{
# TC-MBAM-0023
#-------------

<#
.Synopsis
    Checks, if the MBAM-Server was restarted after the last system update installation.
.DESCRIPTION
    Checks, if the MBAM-Server was restarted after the last system update installation.
.OUTPUTS
    PSCustomObject
#>
    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0023")

    $lastUpdateTimes = Get-LastSoftwareUpdateTimes
    $obj | Add-Member NoteProperty Task("Server restarted after last system update ("+$lastUpdateTimes[0].Title+")") 
    
    if (Get-PendingReboot)
    {      
        $obj | Add-Member NoteProperty Status("Reboot pending")
        $obj | Add-Member NoteProperty Passed("false")
    }
    else
    {
        $lastSystemStartupTime = Get-SystemStartupTime

        if ($lastUpdateTimes -ne $null)
        {
            if($lastUpdateTimes[0].InstalledOn -lt $lastSystemStartupTime)
            {
                $obj | Add-Member NoteProperty Status("System restarted")
                $obj | Add-Member NoteProperty Passed("true")
            }
            else
            {
                $obj | Add-Member NoteProperty Status("'Restart not necessary")
                $obj | Add-Member NoteProperty Passed("true")
            }
        }
        else
        {
            $obj | Add-Member NoteProperty Status("No update found")
            $obj | Add-Member NoteProperty Passed("false")
        }
    }
    
    Write-Output $obj  
}

function Test-MbamASP_NetMVC4
{
# TC-Mbam-0022
#-------------

<#
.Synopsis
    Checks, if ASP.net MVC 4 is installed on the MBAM-Server.
.DESCRIPTION
    Checks, if ASP.net MVC 4 is installed on the MBAM-Server.
.OUTPUTS
    PSCustomObject
#>

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0022")
    $obj | Add-Member NoteProperty Task("ASP.NET MVC 4 Runtime installed") 

    try
    {
        if (Get-Wmiobject Win32_Product | where name -EQ "Microsoft ASP.NET MVC 4 Runtime")
        {
            $obj | Add-Member NoteProperty Status("Installed")
            $obj | Add-Member NoteProperty Passed("true")
        }
        else
        {
            $obj | Add-Member NoteProperty Status("Not installed")
            $obj | Add-Member NoteProperty Passed("false")
        }
    }
    catch
    {
        $obj | Add-Member NoteProperty Status("An error occured, see log file for info.")
        $obj | Add-Member NoteProperty Passed("false")
            
        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }

    Write-Output $obj
}

#
# Client Test
#~~~~~~~~~~~~~~~~

function Test-MbamClientAgentVersion 
{
# TC-Mbam-0030
#-------------

<#
.Synopsis
   Checks Mbam-Agent version
.DESCRIPTION
   Checks the Mbam-Agent version of a client
.INPUTS
   Name of the client in domain; without localhost is used
.OUTPUTS
   System.String The actual versionnumber of the installed Mbam-Agent version as string
.NOTES
   WinRM has to be activated on the remote machine to Get a version number of a remote client
#>
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        [Alias('ClientAgentVersion')]
        [string]$version  
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0030")
    $obj | Add-Member NoteProperty Task("The Mbam-Agent version on client is up to date")


    $currentVersion = Get-MbamClientAgentVersion

    if ($version -eq $currentVersion)
    {
        $obj | Add-Member NoteProperty Status("Version correct, installed version is $currentVersion")
        $obj | Add-Member NoteProperty Passed("true")
    }
    elseif($currentVersion -eq "0")
    {
        $obj | Add-Member NoteProperty Status("No client agent found.")
        $obj | Add-Member NoteProperty Passed("false")    
    }
    else
    {
        $obj | Add-Member NoteProperty Status("Versions differ, installed version is $currentVersion")
        $obj | Add-Member NoteProperty Passed("warning")
    }

    Write-Output $obj
}

function Test-MbamOSDiskProtectionStatus
{
# TC-Mbam-0025
#-------------

<#
.Synopsis
   Checks the protection status of the operating system hard disk drive
.DESCRIPTION
   Checks the protection status of the operating system hard disk drive. Protection status is ok if drive is encrypted and 
   protection is on. The mountpoint of this drive is assumed to be c:\
#>    
    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0025")
    $obj | Add-Member NoteProperty Task("The operating system drive is encrypted and protection is on")

    try 
    {
        if (get-Module -Name BitLocker)
        {
            $volume = Get-BitLockerVolume -MountPoint "C:" 

            if ($volume.ProtectionStatus -eq "On") 
            {
                $obj | Add-Member NoteProperty Status("Protected and encrypted")
                $obj | Add-Member NoteProperty Passed("true")
            }
            elseif (($volume.ProtectionStatus -eq "Off") -and ($volume.VolumeStatus -eq "FullyEncrypted"))
            {
                $obj | Add-Member NoteProperty Status("Encrypted but protection is off")
                $obj | Add-Member NoteProperty Passed("false")
            }
            else
            {
                $obj | Add-Member NoteProperty Status("Not protected")
                $obj | Add-Member NoteProperty Passed("false")
            }
        }
        else
        {
            $volume = get-wmiobject -namespace root\CIMv2\Security\MicrosoftVolumeEncryption -class  Win32_EncryptableVolume -filter "DriveLetter = `"$env:SystemDrive`""

            if ($volume.getProtectionStatus().ProtectionStatus -eq 1)
            {
                $obj | Add-Member NoteProperty Status("Protected and encrypted")
                $obj | Add-Member NoteProperty Passed("true")
            }
            elseif (($volume.getProtectionStatus().ProtectionStatus -eq 0) -and ($volume.getConversionStatus().encryptionPercentage -eq 100))
            {
                $obj | Add-Member NoteProperty Status("Encrypted but protection is off")
                $obj | Add-Member NoteProperty Passed("false")
            }
            else
            {
                $obj | Add-Member NoteProperty Status("Not protected")
                $obj | Add-Member NoteProperty Passed("false")
            }
        }
    }
    catch 
    {
        $obj | Add-Member NoteProperty Status("An error occurred, see logfile for more info.")
        $obj | Add-Member NoteProperty Passed("false")
        
        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }

    Write-Output $obj
}

function Test-MbamDriveProtectionStatus
{
# TC-Mbam-0026
#-------------

<#
.Synopsis 
   Checks the protection status of all local drives.
.DESCRIPTION
   Checks the protection status of all fixed and removable drives. Rom drives like CD oder DVD are not included. 
   Protection status is ok if drive is encrypted and protection is on.
.OUTPUTS
    One protection status per given mounting point entry
.EXAMPLE
    Test-MbamDriveProtectionStatus
#>    

    try 
    {
        if (get-Module -Name BitLocker)
        {
        $mountPoints = Get-Volume | Where {($_.DriveType -like "Fixed") -OR ($_.DriveType -like "Removable")} 
        $i = 1

        foreach($mountPoint in $mountPoints)
        {
            $obj = New-Object PSObject
            $obj | Add-Member NoteProperty Name("TC-Mbam-0026.$i")
            $obj | Add-Member NoteProperty Task("The "+$mountPoint.DriveType+" Drive "+$mountPoint.DriveLetter+" is encrypted and protection is on")

            $volume = Get-BitLockerVolume -MountPoint $mountPoint.DriveLetter 

            if (($volume.ProtectionStatus -eq "On") -and ($volume.VolumeStatus -eq "FullyEncrypted"))
            {
            $obj | Add-Member NoteProperty Status("Protected and encrypted")
            $obj | Add-Member NoteProperty Passed("true")
        }
            elseif (($volume.ProtectionStatus -eq "Off") -and ($volume.VolumeStatus -eq "FullyEncrypted"))
            {
            $obj | Add-Member NoteProperty Status("Encrypted but protection is off")
            $obj | Add-Member NoteProperty Passed("false")
        }
            else
            {
            $obj | Add-Member NoteProperty Status("Not protected")
            $obj | Add-Member NoteProperty Passed("false")
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

function Test-MbamClientSoftwareState
{
# TC-Mbam-0029
#-------------

<#
.Synopsis 
   Checks if the MDOP Mbam client software package is installed 
.DESCRIPTION
   Checks if the MDOP Mbam client software package is installed 
#> 

    try 
    {
        $mbam = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | where DisplayName -eq "MDOP MBAM"

        $obj = New-Object PSObject
        $obj | Add-Member NoteProperty Name("TC-Mbam-0029")
        $obj | Add-Member NoteProperty Task("Status of MDOP MBAM software package")
            
        if(!($mbam -eq $null))
        {
            $obj | Add-Member NoteProperty Status("Installed")
            $obj | Add-Member NoteProperty Passed("true")
        }
        else
        {
            $obj | Add-Member NoteProperty Status("MDOP MBAM Software not found")
            $obj | Add-Member NoteProperty Passed("false")
        } 
    }
    catch
    {
        $obj | Add-Member NoteProperty Status("An error occurred, see logfile for more infos.")
        $obj | Add-Member NoteProperty Passed("false")

        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }

    Write-Output $obj
}

function Test-MbamClientAgentServiceState
{
# TC-Mbam-0029
#-------------

<#
.Synopsis 
   Checks the Mbam client agent status 
.DESCRIPTION
   Checks the Mbam client agent status
#> 
    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0029")
    $obj | Add-Member NoteProperty Task("Status of BitLocker Management Client-Service")
            
    try 
    {
        $agent = Get-service -Name MBAMAgent -ErrorAction Stop

            
        if($agent.Status -eq "Running")
        {
            $obj | Add-Member NoteProperty Status($agent.Status.ToString())
            $obj | Add-Member NoteProperty Passed("true")
        }
        else
        {
            $obj | Add-Member NoteProperty Status($agent.Status.ToString())
            $obj | Add-Member NoteProperty Passed("false")
        } 
    }
    catch
    {
        $obj | Add-Member NoteProperty Status("Service not found")
        $obj | Add-Member NoteProperty Passed("false")

        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }

    Write-Output $obj
}

function Test-MbamTPMStatus
{
# TC-Mbam-0036
#-------------

<#
.Synopsis 
   Checks the TPM status 
.DESCRIPTION
   Checks the TPM status, more specifically if the TPM is present and ready.
#>
    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0036")
    $obj | Add-Member NoteProperty Task("Status of TPM")
    try
    {
        $tpm = Get-tpm

        if ($tpm.TpmPresent -and $tpm.TpmReady)
        {
            $obj | Add-Member NoteProperty Status("TPM present and ready")
            $obj | Add-Member NoteProperty Passed("true")
        }
        elseif ($tpm.TpmPresent -and !$tpm.TpmReady)
        {
            $obj | Add-Member NoteProperty Status("TPM present but not ready")
            $obj | Add-Member NoteProperty Passed("false")
        }
        else
        {
            $obj | Add-Member NoteProperty Status("TPM not present")
            $obj | Add-Member NoteProperty Passed("false")
        }
    }
    catch
    {
        $obj | Add-Member NoteProperty Status("An error occurred, see logfile for more infos.")
        $obj | Add-Member NoteProperty Passed("false")

        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }

    Write-Output $obj
}

function Test-MbamGpos
{
# TC-Mbam-0027
#-------------

    [CmdletBinding()]
    Param(
        [string]$source = "gpo.xml"
    )

    Try
    {
        [xml]$xml = Get-Content $source -ErrorAction Stop


        foreach($policy in $xml.GPO.Policy)
        {
            if($policy.PolicyState -eq 'enabled')
            {
                $obj = New-Object PSObject
                $obj | Add-Member NoteProperty Name("TC-Mbam-0027."+$policy.PolicyID)
                $obj | Add-Member NoteProperty Task("GPO: "+$policy.PolicyName)


                try 
                {
                    if (Get-MbamGpoRuleState -PolicyKey $policy.PolicyKey -PolicyValue $policy.PolicyValue -path $policy.PolicyPath -ErrorAction Stop)
                    {
                        $obj | Add-Member NoteProperty Status("Policy correct and applied")
                        $obj | Add-Member NoteProperty Passed("true")
                    }
                    else
                    {                   
                        $obj | Add-Member NoteProperty Status("Policy value not correct")
                        $obj | Add-Member NoteProperty Passed("warning")
                    }
                }
                catch
                {
                    $obj | Add-Member NoteProperty Status("Policy not applied")
                    $obj | Add-Member NoteProperty Passed("false")
                }            
                
                Write-Output $obj
                $i++
            }
        }
    }
    catch 
    {
        $obj = New-Object PSObject
        $obj | Add-Member NoteProperty Name("TC-Mbam-0027")
        $obj | Add-Member NoteProperty Task("GPOs are correct")
        $obj | Add-Member NoteProperty Status("Reference source gpo.xml or equivalent not found")
        $obj | Add-Member NoteProperty Passed("false")
        Write-Output $obj

        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }    
}

function Test-MbamTpmOwnerShip
{
# TC-Mbam-0037
#-------------

    $tpm = Get-TpmObject

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0037")
    $obj | Add-Member NoteProperty Task("TPM chip is owned by operating system")

    if($tpm -ne $null)
    {
        if($Tpm.IsOwned().isOwned)
        {
            $obj | Add-Member NoteProperty Status("TPM is owned")
            $obj | Add-Member NoteProperty Passed("true")
        }
        else
        {
            $obj | Add-Member NoteProperty Status("TPM not owned")
            $obj | Add-Member NoteProperty Passed("false")
        }
    }
    else
    {
        $obj | Add-Member NoteProperty Status("TPM not found")
        $obj | Add-Member NoteProperty Passed("false")
        # log error
        $msg = "No TPM chip found."
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }

    Write-Output $obj
}

function Test-MbamTpmVersion
{
# TC-Mbam-0041
#-------------

    [CmdletBinding()]
    Param(
        [single]$version = 1.2
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0041")
    $obj | Add-Member NoteProperty Task("TPM chip version is at least $version")

    $tpm = Get-TpmObject

    if($tpm -ne $null)
    {
        $tpmversion = [single]$tpm.SpecVersion.Substring(0,$tpm.SpecVersion.IndexOf(','))
        
        if($tpmversion -ge $version)
        {
            $obj | Add-Member NoteProperty Status("TPM version is $tpmversion")
            $obj | Add-Member NoteProperty Passed("true")
        }
        else
        {
            $obj | Add-Member NoteProperty Status("TPM version is $tpmversion")
            $obj | Add-Member NoteProperty Passed("false")
        }  
    }
    else
    {
        $obj | Add-Member NoteProperty Status("TPM not found")
        $obj | Add-Member NoteProperty Passed("false")
        # log error
        $msg = "No TPM chip found."
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }

    Write-Output $obj
}

function Test-MbamClient2ServerKeyReporting
{
# TC-Mbam-0031 (TC-Mbam-0031.1)
#-------------

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0031.1")
    $obj | Add-Member NoteProperty Task("Client escrowed key to MBAM server")

    try 
    {
        $keyEscrowedTime = Get-WinEvent -FilterHashtable @{logname="microsoft-windows-Mbam/operational";ID=29} -MaxEvents 1 -ErrorAction Stop | select -ExpandProperty TimeCreated
    
        $reportFrequency = Get-item 'HKLM:\SOFTWARE\Policies\Microsoft\FVE\MDOPBitLockerManagement' -ErrorAction Stop | Get-ItemProperty | select -ExpandProperty "clientWakeupFrequency"

        $lastStartup = Get-SystemStartupTime
        
        $time = (Get-Date).AddMinutes(-$reportFrequency)

            
        if ($lastStartup -gt $time)
        {
            if($keyEscrowedTime -gt $time)
            {
                $obj | Add-Member NoteProperty Status("Key escrowed at $keyEscrowedTime")
                $obj | Add-Member NoteProperty Passed("true")
            }
            else
            {
                $obj | Add-Member NoteProperty Status("Last system startup within report frequency, key not escrowed yet")
                $obj | Add-Member NoteProperty Passed("warning")
            }
        }
        else
        {
            if($keyEscrowedTime -gt $time)
            {
                $obj | Add-Member NoteProperty Status("Key escrowed at $keyEscrowedTime")
                $obj | Add-Member NoteProperty Passed("true")
            }
            else
            {
                $obj | Add-Member NoteProperty Status("No key escrowed within regular frequency")
                $obj | Add-Member NoteProperty Passed("false")
            }
        }
    }
    catch
    {
        $obj | Add-Member NoteProperty Status("An error occurred, see log file for more info.")
        $obj | Add-Member NoteProperty Passed("false")

        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }

    Write-Output $obj
}

function Test-MbamClient2ServerStatusReporting
{
# TC-Mbam-0031 (TC-Mbam-0031.2)
#-------------

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-Mbam-0031.2")
    $obj | Add-Member NoteProperty Task("Client reported status to MBAM server")

    try 
    {
        $statusReportingTime = Get-WinEvent -FilterHashtable @{logname="microsoft-windows-Mbam/operational";ID=3} -MaxEvents 1 -ErrorAction Stop | select -ExpandProperty TimeCreated
    
        $statusReportingFrequency = Get-item 'HKLM:\SOFTWARE\Policies\Microsoft\FVE\MDOPBitLockerManagement' -ErrorAction Stop | Get-ItemProperty | select -ExpandProperty "StatusReportingFrequency"
        
        $lastStartup = Get-SystemStartupTime
        
        $time = (Get-Date).AddMinutes(-$statusReportingFrequency)

        if ($lastStartup -gt $time)
        {
            if($statusReportingTime -gt $time)
            {
                $obj | Add-Member NoteProperty Status("Status reported at $statusReportingTime")
                $obj | Add-Member NoteProperty Passed("true")
            }
            else
            {
                $obj | Add-Member NoteProperty Status("Last system startup within report frequency, status not reported yet")
                $obj | Add-Member NoteProperty Passed("warning")
            }
        }
        else
        {
            if($statusReportingTime -gt $time)
            {
                $obj | Add-Member NoteProperty Status("Status reported at $statusReportingTime")
                $obj | Add-Member NoteProperty Passed("true")
            }
            else
            {
                $obj | Add-Member NoteProperty Status("No status reported within regular frequency")
                $obj | Add-Member NoteProperty Passed("false")
            }
        }
    }
    catch
    {
        $obj | Add-Member NoteProperty Status("An error occurred, see log file for more info.")
        $obj | Add-Member NoteProperty Passed("false")

        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
    }

    Write-Output $obj
}

function Test-BitlockerDriverVersion
{
# TC-Mbam-0049
#-------------

<#
.Synopsis 
    Checks, if the BitLocker driver version is up to date.
.DESCRIPTION
    Checks, if the BitLocker driver version is up to date. At the moment this test only works for Windows 7 SP1 , 8.1 and 10.
#>

try
{
    $fileVersion = ([System.Diagnostics.FileVersionInfo]::GetVersionInfo("c:\windows\system32\drivers\fvevol.sys").ProductVersion).replace(".","")
    $osVersion = Get-CimInstance Win32_OperatingSystem | select -ExpandProperty Version
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
    "6.1.7601" { $expectedFileVersion = "61760123003"; break }
    "6.3.9600" { $expectedFileVersion = "63960017031"; break }
    "10.0.15063" { $expectedFileVersion = "100150630"; break }
    default { $expectedFileVersion = "0"; break }
}

# Create the test result object
$obj = New-Object PSObject
$obj | Add-Member NoteProperty Name("TC-Mbam-0049")
$obj | Add-Member NoteProperty Task("The BitLocker driver version is correct.")

# Driver version matches
if ($expectedFileVersion -eq $fileVersion)
{
    $obj | Add-Member NoteProperty Status("Driver is up to date.")
    $obj | Add-Member NoteProperty Passed("true")
}

# Operating system not in the list
elseif ($expectedFileVersion -eq 0)
{
    $obj | Add-Member NoteProperty Status("Operating system could not be identified.")
    $obj | Add-Member NoteProperty Passed("false")
}

# A newer driver version is available
elseif ($expectedFileVersion -gt $fileVersion)
{
    $obj | Add-Member NoteProperty Status("Driver version is older than expected.")
    $obj | Add-Member NoteProperty Passed("warning")
}

# A driver version with a higher version number is already installed (
elseif ($expectedFileVersion -lt $fileVersion)
{
    $obj | Add-Member NoteProperty Status("Driver version is higher than expected.")
    $obj | Add-Member NoteProperty Passed("warning")
}

Write-Output $obj
}



# Export functions and variables, access is restricted by manifest file if needed
Export-ModuleMember -Function '*'
Export-ModuleMember -Variable '*'