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
    Last change:      08/17/2018
    Version:          1.0
    State:            Approved
#>

<# 
    Module for testing Windows Server related issues.

#>

Using module TapResultClass

#region Imports
Import-Module LogFileModule -ErrorAction SilentlyContinue

# Load settings from setting file
$winSrvExtensionModulePath = (Get-Module -ListAvailable WinSrvExtensionModule).Path
$baseDir = (Get-Item $winSrvExtensionModulePath).Directory.Parent.Fullname+"\Settings"
Import-LocalizedData -FileName Settings.psd1 -BaseDirectory $baseDir -BindingVariable "ConfigFile"

#endregion

#region Logfile settings
# Set the path and name of standard log file to path and name configured in settings
$LogPath = $ConfigFile.Settings.LogFilePath
$LogName = (Get-date -Format "yyyyMMdd")+"_"+$ConfigFile.Settings.LogFileName
#endregion

#region Table of content
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
#endregion


#region 1 Test functions
# ----------------
#
# Section for all Test-functions inside this module.
#
############################################################## 


#region 1.1 Public test-functions
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

function Test-LocalAdmins
{
<#
.Synopsis
    Tests if the members of the local admin group matches the list of members in the file.
.DESCRIPTION
    Tests if the members of the local admin group matches the list of members in the file.
.PARAMETER knownAdmins
    A list of SamAccountNames of members which are assumed to be in the local admin group. Use new-LocalAdminsFile.ps1 in module directory to initally create a snapshot
    of local admin group.
.PARAMETER moduleID
    The optional moduleID if the test is called by another TAP module
.NOTES
    ID  FBP-WinSrv-0005
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [Alias('LocalAdminGroupMembers')]
    [string[]] $knownAdmins,

    [String]$moduleId
)

    if (($null -eq $moduleID) -or ($moduleID -eq "") ) { $moduleID = "N/A" }
    
    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[FBP-WinSrv-0005]" + [System.Environment]::NewLine
    $messageBag += "Module ID: $moduleID"

    $obj = [TapResult]::New("FBP-WinSrv-0005", "$moduleId", "Members in local admin group are correct") 


    $admins = Get-LocalAdmins

    if (-not($null -eq $admins) -and -not($null -eq $knownAdmins))
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
            $obj.Status = "Not listed members found ($unexpectedCounter): $nl $unexpected $nl Missing members($missingCounter): $nl $missing"
            $obj.Passed = 2
            Write-LogFile -Path $LogPath -name $LogName -message "Local admins - not listed members found: $unexpected $nl Missing members: $missing" -Level Error
        }
        elseif ($unexpected) 
        {
            $obj.Status = "Not listed members found($unexpectedCounter): $nl $unexpected"
            $obj.Passed = 2
            Write-LogFile -Path $LogPath -name $LogName -message "Local admins - not listed members found: $unexpected" -Level Error   
        }
        elseif ($missing)
        {
            $obj.Status = "Missing members($missingCounter): $nl $missing"
            $obj.Passed = 3
            Write-LogFile -Path $LogPath -name $LogName -message "Local admins - missing members: $missing" -Level Warning
        }
        else 
        {
            $obj.Status = "All correct"
            $obj.Passed = 1
        }
    }
    else
    {
        $obj.Status = "An error occured while checking."
        $obj.Passed = 4
        Write-LogFile -Path $LogPath -name $LogName -message "An error occured. Either local admins could not be received or file knownLocalAdmins.txt is empty/could not be read"
    }

    Write-Output $obj
}

function Test-WinSrvSccmClientUpdates
{
<#
.Synopsis
    Tests if deployed and applicable updates are installed.
.DESCRIPTION
     Tests if deployed and applicable updates are installed. If updates are available a warning is returned with a list of applicable updates in the status property of the object.
.PARAMETER moduleID
    The optional moduleID if the test is called by another TAP module
.NOTES
    ID  FBP-WinSrv-0006 
#>
[CmdletBinding()]
Param(
    [String]$moduleId
)

    if (($null -eq $moduleID) -or ($moduleID -eq "") ) { $moduleID = "N/A" }
    
    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[FBP-WinSrv-0006" + [System.Environment]::NewLine
    $messageBag += "Module ID: $moduleID"

    $obj = [TapResult]::New("FBP-WinSrv-0006", "$moduleId", "All applicable updates via SCCM are installed.") 

    try 
    {
        $SCCMUpdates = Get-CimInstance -Namespace 'root\ccm\ClientSDK' -ClassName 'CCM_SoftwareUpdate' -ErrorAction Stop

        if ($null -eq $SCCMUpdates)
        {
            # No updates applicable
            $obj.Status = "No updates appliable"
            $obj. Passed = 1
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
            $obj.Status = "The following updates are applicable" + $nl + $status
            $obj.Passed = 3

            # Also log applicable updates in logfile
            Write-LogFile -Path $LogPath -name $LogName -message $status -Level Warning
        }
    }
    catch
    {
        $obj.Status = "SCCM client not installed."
        $obj.Passed = 1
        Write-LogFile -Path $LogPath -name $LogName -message "CCM class not found. SCCM client not installed?" -Level Error
    }    

    Write-Output $obj
}

function Test-LastUserLogins
{
<#
.Synopsis
   Checks, if only expected users have logged in on the server.
.DESCRIPTION
   Checks, if only expected users have logged in on the server.
.PARAMETER acceptedUsers
    Users which are allowed to login
.PARAMETER moduleID
    The optional moduleID if the test is called by another TAP module
.NOTES
    ID  FBP-WinSrv-0007
#>
[CmdletBinding()]
Param(
    [string[]]$acceptedUsers,

    [String]$moduleId
)
    
    if (($null -eq $moduleID) -or ($moduleID -eq "") ) { $moduleID = "N/A" }
    
    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[FBP-WinSrv-0007]" + [System.Environment]::NewLine
    $messageBag += "Module ID: $moduleID"

    $obj = [TapResult]::New("FBP-WinSrv-0007", "$moduleId", "Only expected logins within last 24h on machine") 

    $logins = Get-UserLogins

    # Check, if we have any login
    if ($null -ne $logins)
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
        $obj.Status = "Unexpected logins found: $nl $unexpected"
        $obj.Passed = 3
        Write-LogFile -Path $LogPath -name $LogName -message "Unexpected logins found: $unexpected" -Level Warning   
    }
    else 
    {
        $obj.Status = "No unexpected logins found"
        $obj.Passed = 1
    }

    Write-Output $obj
}

function Test-WinSrvMaintenanceModeOn
{
<#
.Synopsis
   Checks, if maintenance mode is on for server.
.DESCRIPTION
   Checks, if maintenance mode is on for server.
.PARAMETERS pathToLogFile
    Filepath to the MMTool log file
.PARAMETER moduleID
    The optional moduleID if the test is called by another TAP module
.NOTES
    ID  FBP-WinSrv-0008
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$pathToLogFile,

    [String]$moduleId
    )

    if (($null -eq $moduleID) -or ($moduleID -eq "") ) { $moduleID = "N/A" }
    
    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[FBP-WinSrv-0008]" + [System.Environment]::NewLine
    $messageBag += "Module ID: $moduleID"

    $obj = [TapResult]::New("FBP-WinSrv-0008", "$moduleId", "Maintenance mode for server is off") 


    if ((Get-MaintenanceMode $pathToLogFile) -eq $false)
    {
        $obj.Status = "Maintenance mode OFF"
        $obj. Passed = 1   
    }
    else 
    {
        $obj.Status = "Maintenance mode ON"
        $obj.Passed = 3
        Write-LogFile -Path $LogPath -name $LogName -message "Maintenance mode ON" -Level Warning   
    }

    Write-Output $obj
}

function Test-WinSrvFirewallPort443State
{
<#
.Synopsis
   Checks, if the firewall for IIS rule on port 443 allows inbound traffic.
.DESCRIPTION
   Checks, if the firewall for IIS rule on port 443 allows inbound traffic.
.PARAMETER moduleID
    The optional moduleID if the test is called by another TAP module
.NOTES
    ID  FBP-WinSrv-0009
#>
[CmdletBinding()]
Param(
    [String]$moduleId
)     
     
    if (($null -eq $moduleID) -or ($moduleID -eq "") ) { $moduleID = "N/A" }
    
    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[FBP-WinSrv-0008]" + [System.Environment]::NewLine
    $messageBag += "Module ID: $moduleID"

    $obj = [TapResult]::New("FBP-WinSrv-0009", "$moduleId", "Port 443 allows inbound traffic to reach the webserver") 

    try
    {
        # check firewall rule of port 443 (standard iis rule)
        $rule = Get-NetFirewallRule | Where-Object -Property name -eq IIS-WebserverRole-HTTPS-In-TCP 
        
        if($null -ne $rule)
        {     
            if ($rule.Enabled -eq "true")
            {
                if ($rule.Action -eq "Allow")
                {
                    $obj.Status = "Enabled, Allow"
                    $obj.Passed = 1
                }
                else
                {
                    $obj.Status = "Enabled, Block"
                    $obj.Passed = 2
                }
            }
            else
            {
                $obj.Status = "Disabled"
                $obj.Passed = 1
            }  
        }
        else
        {
            # Standard IIS-Webserver rule for port 443 not found
            $obj.Status = "Not found"
            $obj.Passed = 1
        }
    }
    catch
    {
        $obj.Status = "An error occured, see log file for more info!"
        $obj.Passed = 4
        Write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error
    }

    Write-Output $obj
}

#endregion

#region 1.2 Private test-functions
# ---------------------
#
# Section for test-functions used in other functions inisde this module.
# Designated as private but can also be used outside this module
#=======================================================================

#endregion

#endregion

#region 2 Helper functions
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

function Get-UserLogins
{
[CmdletBinding()]
Param(
    [DateTime]$date = (Get-Date).AddDays(-1)
)

    Get-CimInstance -class Win32_NetworkLoginProfile |Select-Object name, caption, @{Name="lastlogin"; Expression={$_.ConvertToDateTime($_.LastLogon)}} | Where-Object lastlogin -GT $date
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

    $members = $group.psbase.invoke("members")  | ForEach-Object {
        $_.GetType().InvokeMember("Name",  'GetProperty',  $null,  $_, $null)
    }
    $admins = @()

    if(Get-Module ActiveDirectory)
    {
        foreach($member in $members)
        {  
            try {      
                # Try if $member is a AD group and get all members of this group including all nested groups      
                $admins += (Get-ADGroupMember $member -Recursive | Select-Object -ExpandProperty SamAccountName)
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
    Write-Output $admins | Select-Object -Unique
}

function Test-WinSrvRestartNescessary
{
<#
.Synopsis
   Checks, if the server must be restarted within the next X days.
.DESCRIPTION
   Checks, if the server must be restarted within the next X days.
.PARAMETER wihtinDays
    Optional number of days to check
#>
[Cmdletbinding()]
Param(
    [int]$withinDays = 7
)

    $restart = "NO"
    # If we have a pending reboot, system definitely has to restart
    if (Get-PendingReboot) { $restart = "YES" }

    # Otherwise check, if there are updates to install within the next $withDays
    else
    {
        try
        {
            $date = (Get-Date).AddDays($withinDays)
            
            try
            {
                Get-CimInstance -Namespace 'root\ccm\ClientSDK' -ClassName 'CCM_SoftwareUpdate' -ErrorAction Stop `
                | Select-Object -ExpandProperty Deadline `
                |   ForEach-Object { if ($_.Deadline -le $date) 
                        { 
                            $restart = "YES"
                            #break;
                        } 
                    }
            }
            catch
            {
                $restart = "SCCM client not installed"
                # log error
                write-LogFile -Path $LogPath -name $LogName -message "CCM class not found. SCCM client not installed?" -Level Error
            }

        }
        catch
        {
            $restart = "SCCM client not installed"
            # log error
            write-LogFile -Path $LogPath -name $LogName -message "CCm class not found. SCCM client not installed?" -Level Error
        } 
    }

    Write-Output $restart
}

function Get-OperatingSystemInfo
{
<#
.Synopsis
   Gets a bunch of system information.
.DESCRIPTION
   Gets a bunch of system information like free RAM, free disk space, OS version etc.
#>

    Get-CimInstance Win32_OperatingSystem | Select-Object *
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
[CmdletBinding()]
Param()
   
    # Get log record with id 12 of source kernel general and return time
    Get-WinEvent -FilterHashtable @{Logname='System'; ProviderName='Microsoft-Windows-Kernel-General'; ID=12} -MaxEvents 1 | Select-Object @{label='TimeCreated';expression={$_.TimeCreated.ToString("yyyy-M-d HH:mm:ss")}} -ExpandProperty TimeCreated

}

function Get-UpdateHistory 
{
[CmdletBinding()]
Param(
    # number of update events
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
    
    if ($null -eq $updates)
    {
        Write-Output "No updates found"
    }
    else
    {
        Write-Output $updates[0].TimeCreated
        Write-Output "<ul>"

        foreach($update in $updates)
        {
            Write-Output -InputObject "<li>$($update.UpdateName)</li>"
        }
        Write-Output "</ul>"
    }
}

function Get-FormattedSccmUpdateInformation
{
    try
    {
        $updates = Get-LastInstalledSccmUpdateGroup -ErrorAction Stop
    
    
        if ($null -eq $updates)
        {
            Write-Output "No updates found"
        }
        else
        {
            Write-Output $updates[0].TimeCreated"<br/><br/>"
            Write-Output "<ul>"

            foreach($update in $updates)
                    {
            Write-Output "<li>"$($update.UpdateName)"</li>"
        }
            Write-Output "</ul>"
        }
    }
    catch
    {
        Write-Output "SCCM client not installed"
    }
}

function Measure-HibertationTime
{
<#
.Synopsis
   Counts the time the machine was in hibernation mode.
.DESCRIPTION
   Counts the time the machine was in hibernation mode. Returns a TimeSpan with the hibernation time.
.PARAMETER $since
    DateTime object at which the measurement should start which could be for example the last system start.
#>
[CmdletBinding()]
Param(
    [Parameter(ValueFromPipeline=$true)]
    [DateTime]$since
)
    [TimeSpan]$counter = 0
    Get-EventLog -LogName system -InstanceId 1 -Source Microsoft-Windows-Power-TroubleShooter | Where-Object TimeGenerated -gt $since |
    ForEach-Object {
        [DateTime]$sleeptime = $_.ReplacementStrings[0]
        [DateTime]$wakeTime = $_.ReplacementStrings[1]
        $counter += $wakeTime - $sleeptime    
    }

    Write-Output $counter
}

function Measure-SystemUpTime
{
<#
.Synopsis
    Measures the system up time.
.DESCRIPTION
    Measures the system up time. The up time is calculate by the last system start minus hibernation time.
#>
[CmdletBinding()]
Param()

    $startUp = Get-SystemStartupTime

    Write-Output ((New-TimeSpan($startUp)) - ($startUp | Measure-HibertationTime))
}

#endregion
