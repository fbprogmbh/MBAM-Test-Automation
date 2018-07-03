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

<#

    Author(s):        Dennis Esly | dennis.esly@fb-pro.com
    Date:             05/25/2018
    Last change:      05/25/2018
    Version:          0.1
    State:            Draft
#>

<# 
    Module for testing Windows Server related issues.

#>

Using module TapResultClass

Import-Module ..\LogFileModule\LogFileModule.psm1 -ErrorAction SilentlyContinue

# Load settings from setting file
$ConfigFile = Import-LocalizedData -FileName Settings.psd1


# Set the path and name of standard log file to path and name configured in settings
$LogPath = $ConfigFile.Settings.LogFilePath
$LogName = (Get-date -Format "yyyyMMdd")+"_"+$ConfigFile.Settings.LogFileName


# Table of content
# ================
#
# 1 .........Test-functions 
# 
# 1.1 .......Public test-functions
# 
# 1.2 .......Private test-functions 
#
# 2 .........Helper functions
#
# ---------------------------------------------------------



# 1 Test functions
# ----------------
#
# Section for all Test-functions inside this module.
#
############################################################## 


# 1.1 Public test-functions
# ---------------------
#
# Section for test-functions representing a test case
#=====================================================


function Test-WinSrvFeatureState 
{
<#
.Synopsis
    Checks, if expected Windows Server features is installed
.DESCRIPTION
    Checks, if expected Windows Server features is installed
.PARAMETER feature
    A feature or a list of features
.PARAMETER moduleID
    The optional moduleID if the test is called by another TAP module
.NOTES
    ID  FBP-WinSrv-0001
#>   
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [String[]]$feature,
    
    [String]$moduleID 
)
    if (($null -eq $moduleID) -or ($moduleID -eq "") ) { $moduleID = "N/A" }
    
    $i = 1

    foreach($item in $feature)
    {
        try
        {
            $f = Get-WindowsFeature $item -ErrorAction Stop

            $messageBag = "Additional info:" + [System.Environment]::NewLine
            $messageBag += "ID:[FBP-WinSrv-0001]" + [System.Environment]::NewLine
            $messageBag += "Module ID: $moduleID"
   
            $name = $f.DisplayName
            if ( ($feature.Count -gt 1) -and ($moduleID -ne "N/A") )
            {
                $module = "$moduleID.$i"
            }
            else
            {
                $module = $moduleID
            }
            $obj = [TapResult]::New("FBP-WinSrv-0001", "$module", "Windows feature $name ($item) is installed")          
            $obj.Status = $f.InstallState.ToString()
        
            if ($f.Installed)
            {
                $obj.Passed = 1
            }
            elseif (-not $f.Installed)
            {
                $obj.Passed = 2

                $msg = "Windows feature $name ($item) is not installed"+[System.Environment]::NewLine
                $msg += $messageBag
                Write-EventLog -LogName "FBPRO-TAP" -Source "WinSrv-TAP" -Message $msg -EventId 1 -EntryType Error -Category 0
            }
        
            $i++
        }
        catch
        {
            $obj = [TapResult]::New("FBP-WinSrv-0001", "$moduleID", "Windows feature ($item) is installed")  
            $obj.Status = "Windows feature $item not found"
            $obj.Passed = 2  

            # log error
            $e = "Windows feature $item not found"
            $e += $_.Exception.toString()
            $e += "; " + $_.ScriptStackTrace.toString()
            Write-LogFile -Path $LogPath -name $LogName -message $e -Level Error

            $msg = "Windows feature $item not found"+[System.Environment]::NewLine
            $msg += $messageBag+[System.Environment]::NewLine
            $msg += $e
            Write-EventLog -LogName "FBPRO-TAP" -Source "WinSrv-TAP" -Message $msg -EventId 2 -EntryType Error -Category 0
        }

        Write-Output $obj
    }
}

function Test-WinSrvServiceState
{
<#
.Synopsis
    Checks, if the given service is running
.DESCRIPTION
    Checks, if the given service is running
.PARAMETER service
    A service or a list of services
.PARAMETER moduleID
    The optional moduleID if the test is called by another TAP module
.NOTES
    ID  FBP-WinSrv-0002
#>
[CmdletBinding()]
Param(   
    [String[]]$service,
    [String]$moduleId
)
    
    if (($null -eq $moduleID) -or ($moduleID -eq "") ) { $moduleID = "N/A" }
    
    $i = 1

    foreach($item in $service)
    {

        $s = Get-Service | Where-Object name -eq $item

        $messageBag = "Additional info:" + [System.Environment]::NewLine
        $messageBag += "ID:[FBP-WinSrv-0002]" + [System.Environment]::NewLine
        $messageBag += "Module ID: $moduleID"

        if ( ($service.Count -gt 1) -and ($moduleID -ne "N/A") )
        {
            $module = "$moduleID.$i"
            $i++
        }
        else
        {
            $module = $moduleID
        }
        $name = $s.DisplayName

        $obj = [TapResult]::New("FBP-WinSrv-0002", "$module", "Windows service $name ($item) is running")     

        if ($null -ne $s)
        {
            # service found, add status 
            $obj.Status = ($s.Status).ToString()

            if ($s.Status -eq "running")
            {
                $obj.Passed = 1
            }
            else 
            {
                # service paused or stopped
                $obj.Passed = 3

                $msg = "Windows service $item not running"+[System.Environment]::NewLine
                $msg += $messageBag
                Write-EventLog -LogName "FBPRO-TAP" -Source "WinSrv-TAP" -Message $msg -EventId 4 -EntryType Warning -Category 0
            }
        }
        else 
        {        
            $obj = [TapResult]::New("FBP-WinSrv-0002", "$moduleID", "Windows service ($item) is running")  
            $obj.Status = "Windows service $item not found"
            $obj.Passed = 2  

            # log error
            $e = "Windows service $item not found."
            Write-LogFile -Path $LogPath -name $LogName -message $e -Level Error

            $msg = "Windows service $item not found"+[System.Environment]::NewLine
            $msg += $messageBag
            Write-EventLog -LogName "FBPRO-TAP" -Source "WinSrv-TAP" -Message $msg -EventId 3 -EntryType Error -Category 0
        }
        
        Write-Output $obj
    }
}

function Test-WinSrvSoftwareInstallState
{
<#
.Synopsis
    Checks, if the software given by parameter is installed.
.DESCRIPTION
    Checks, if the software given by parameter is installed. Gathers installed software from registry and then compare both.
.PARAMETER softwareList
    A software name or a list of software names
.PARAMETER moduleID
    The optional moduleID if the test is called by another TAP module
.NOTES
    ID  FBP-WinSrv-0003
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [String[]]$softwareList,

    [String]$moduleId
)

    if (($null -eq $moduleID) -or ($moduleID -eq "") ) { $moduleID = "N/A" }
    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[FBP-WinSrv-0003]" + [System.Environment]::NewLine
    $messageBag += "Module ID: $moduleID"

    Write-Verbose "[FBP-WinSrv-0003]: Gathering installation information from registry"
    try 
    {
        $installedSoftList = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName | Select-Object -ExpandProperty DisplayName
        $installedSoftList += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName | Select-Object -ExpandProperty DisplayName | Select-Object -Unique
        $installedSoftList = $installedSoftList | Select-Object -Unique
    }
    catch
    {
        $obj = [TapResult]::New("FBP-WinSrv-0003", "$module", "Software is installed")    
        $obj.Status("An error occured, see log file for info.")
        $obj.Passed = 4
            
        # log error
        $e = $_.Exception.toString()
        $e += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $e -Level Error

        $msg = "Error in gathering installation information from the registry"+[System.Environment]::NewLine
        $msg += $messageBag+[System.Environment]::NewLine
        $msg += $e
        Write-EventLog -LogName "FBPRO-TAP" -Source "WinSrv-TAP" -Message $msg -EventId 5 -EntryType Error -Category 0

        # return object and stop the script from continuing because we cannot check faulty list
        Write-Output $obj
        break
    }
    
    $i = 1

    Write-Verbose "[FBP-WinSrv-0003]: Comparing software list"
    foreach($software in $softwareList)
    {
        if ( ($softwareList.Count -gt 1) -and ($moduleID -ne "N/A") )
        {
            $module = "$moduleID.$i"
            $i++
        }
        else { $module = $moduleID }


        $obj = [TapResult]::New("FBP-WinSrv-0003", "$module", "$software is installed")   

        try
        {
            if ($installedSoftList -contains $software)
            {
                $obj.Status = "Installed"
                $obj.Passed = 1
            }
            else
            {
                $obj.Status = "Not installed"
                $obj.Passed = 2

                $msg = "$software not installed on system"+[System.Environment]::NewLine
                $msg += $messageBag
                Write-EventLog -LogName "FBPRO-TAP" -Source "WinSrv-TAP" -Message $msg -EventId 6 -EntryType Error -Category 0
            }
        }
        catch
        {
            $obj.Status  ="An error occured, see log file for info."
            $obj.Passed =4 
                        
            # log error
            $e = $_.Exception.toString()
            $e += "; " + $_.ScriptStackTrace.toString()
            write-LogFile -Path $LogPath -name $LogName -message $e -Level Error

            $msg = "$software not installed on system"+[System.Environment]::NewLine
            $msg += $messageBag+[System.Environment]::NewLine
            $msg += $e
            Write-EventLog -LogName "FBPRO-TAP" -Source "WinSrv-TAP" -Message $msg -EventId 6 -EntryType Error -Category 0
        }

        Write-Output $obj  
        $i++ 
    } 
}

function Test-WinSrvRestartedAfterUpdate
{
<#
.Synopsis
    Checks, if the Windows Server was restarted after the last system update installation.
.DESCRIPTION
    Checks, if the Windows Server was restarted after the last system update installation.
.PARAMETER moduleID
    The optional moduleID if the test is called by another TAP module
.NOTES
    ID  FBP-WinSrv-0004
#>
[CmdletBinding()]
Param(
    [String]$moduleId
)    
    if (($null -eq $moduleID) -or ($moduleID -eq "") ) { $moduleID = "N/A" }
    
    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[FBP-WinSrv-0004]" + [System.Environment]::NewLine
    $messageBag += "Module ID: $moduleID"
    
    $lastUpdateTimes = Get-LastSoftwareUpdateTime
    $obj = [TapResult]::New("FBP-WinSrv-0004", "$moduleId", "Server restarted after last system update ("+$lastUpdateTimes[0].Title+")") 
    
    if (Get-PendingReboot)
    {      
        $obj.Status = "Reboot pending"
        $obj.Passed = 2 
    }
    else
    {
        $lastSystemStartupTime = Get-SystemStartupTime

        if ($null -ne $lastUpdateTimes)
        {
            if($lastUpdateTimes[0].InstalledOn -lt $lastSystemStartupTime)
            {
                $obj.Status = "System restarted"
                $obj.Passed = 1
            }
            else
            {
                $obj.Status = "Restart not necessary"
                $obj.Passed = 1
            }
        }
        else
        {
            $obj.Status = "No update found"
            $obj.Passed = 2
        }
    }
    
    Write-Output $obj  
}


# 1.2 Private test-functions
# ---------------------
#
# Section for test-functions used in other functions inisde this module.
# Designated as private but can also be used outside this module
#=======================================================================




# 2 Helper functions
# ---------------------
#
# Helper functions used in this module
#=====================================================

function Get-LastSoftwareUpdateTime
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

function Get-PendingReboot
{
<#
.Synopsis
    Checks if there is a reboot pending
.DESCRIPTION
    This function looks for a registry branch with the key 'RebootPending'. If it does not exists, then no reboot is necessary.   
.OUTPUTS
    $true if reboot is pending, $false otherwise 
#> 
[CmdletBinding()]
Param()

    $reboot = $false

    if (Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction SilentlyContinue)
    {
        $reboot = $true
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

.PARAMETER date
    The date from which logins are returned    
#>
[CmdletBinding()]
Param(
    [DateTime]$startDate = (Get-Date).AddDays(-7)
)
    
    $log = Get-Eventlog -LogName Security -after $startDate

    $log | Where-Object {$_.EventID -eq 4624} | Where-Object {($_.ReplacementStrings[8] -eq 2) -or ($_.ReplacementStrings[8] -eq 10)}  | ForEach-Object {
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
    } | Where-Object {$_.User -notlike "DWM-*"}

}