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
    Date:             04/20/2018
    Last change:      05/03/2018
    Version:          0.1
    State:            Draft
#>

<# 
    Module for testing Active Directory related issues.

#>

Using module TapResultClass

Import-Module ActiveDirectory -ErrorAction SilentlyContinue
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






# 1 Test function
# ---------------
#
# Section for all "public" Test-* functions inside this module.
#
##############################################################

<#
.Synopsis
    Tests, if the given service account is enabled.
.DESCRIPTION
    Tests, if the given service account is enabled. It takes SAMAccount name or SID to get informations from Active Directory.
    Therefore the Active Directory module must be installed on the system (or RSAT).
.PARAMETER identity
    Either the SAMAccountName or the SID of the service account
.PARAMETER type
    The type of the identity, SamAccountName oder Sid
.PARAMETER moduleID
    An optional ID of the module calling this function
.EXAMPLE
    PS C:\> Test-ADSvcAccEnabled -identity sara.oster -type SamAccountName -moduleID "TC-MBAM-0001"

    ID       : FBP-AD-0001
    moduleID : TC-MBAM-0001
    Task     : Service account enabled
    Status   : true
    Passed   : Passed
.NOTES 
    ID FBP-AD-0001
#>
function Test-ADSvcAccEnabled
{
[CmdletBinding()]
Param(
     # the identity depending on type (SamAccountName, SID)
    [Parameter(Mandatory=$true)]
    [System.String]$identity,

    # the identities type
    [ValidateSet('SamAccountName','Sid')]
    [Parameter(Mandatory=$true)]
    [System.String]$type,

    # optional module ID
    [System.String]$moduleID
)
    
    if ($moduleID -eq "") { $moduleID = "N/A"}

    $obj = [TapResult]::New("FBP-AD-0001", $moduleID, "Service account enabled")

    Write-Output (Test-ADAccountProperty -TapResultObject $obj -identity $identity -type $type -property "Enabled" -propertyValue "true" )
     
}

function Test-ADSvcAccPwdExpired
{
<#
.Synopsis
    Tests, if the password of the Service Account has expired.
.DESCRIPTION
    Tests, if the password of the Service Account has expired. It takes SAMAccount name or SID to get informations from Active Directory.
    Therefore the Active Directory module must be installed on the system (or RSAT).
.PARAMETER identity
    Either the SAMAccountName or the SID of the service account
.PARAMETER type
    The type of the identity, SamAccountName oder Sid
.PARAMETER moduleID
    An optional ID of the module calling this function
.EXAMPLE
    PS C:\> Test-ADSvcAccPwdExpired -identity sara.oster -type SamAccountName 

    ID       : FBP-AD-0002
    moduleID : N/A
    Task     : Password has expired
    Status   : False
    Passed   : Passed
.NOTES 
    ID FBP-AD-0002
#>
[CmdletBinding()]
Param(
     # the identity depending on type (SamAccountName, SID)
    [Parameter(Mandatory=$true)]
    [System.String]$identity,

    # the identities type
    [ValidateSet('SamAccountName','Sid')]
    [Parameter(Mandatory=$true)]
    [System.String]$type,

    # optional module ID
    [System.String]$moduleID
)
    
    if ($moduleID -eq "") { $moduleID = "N/A"}

    $obj = [TapResult]::New("FBP-AD-0002", $moduleID, "Password has expired")

    Write-Output (Test-ADAccountProperty -TapResultObject $obj -identity $identity -type $type -property "PasswordExpired" -propertyValue $false)
     
}

function Test-ADSvcAccPwdNeverExpires
{
<#
.Synopsis
    Tests, if the password of the Service Account never expires.
.DESCRIPTION
    Tests, if the password of the Service Account never expires. It takes SAMAccount name or SID to get informations from Active Directory.
    Therefore the Active Directory module must be installed on the system (or RSAT).
.PARAMETER identity
    Either the SAMAccountName or the SID of the service account
.PARAMETER type
    The type of the identity, SamAccountName oder Sid
.PARAMETER moduleID
    An optional ID of the module calling this function
.EXAMPLE
    PS C:\> Test-ADSvcAccPwdNeverExpires -identity sara.oster -type SamAccountName 

    ID       : FBP-AD-0003
    moduleID : N/A
    Task     : Password never expires
    Status   : True
    Passed   : Passed
.NOTES
    ID FBP-AD-0003
#>
[CmdletBinding()]
Param(
     # the identity depending on type (SamAccountName, SID)
    [Parameter(Mandatory=$true)]
    [System.String]$identity,

    # the identities type
    [ValidateSet('SamAccountName','Sid')]
    [Parameter(Mandatory=$true)]
    [System.String]$type,

    # optional module ID
    [System.String]$moduleID
)
    
    if ($moduleID -eq "") { $moduleID = "N/A"}

    $obj = [TapResult]::New("FBP-AD-0003", $moduleID, "Password never expires")

    Write-Output (Test-ADAccountProperty -TapResultObject $obj -identity $identity -type $type -property "PasswordNeverExpires" -propertyValue $true)
     
}

function Test-ADSvcAccSPNs
{
<#
.Synopsis
    Tests the SPNs for the Service Account
.DESCRIPTION
    Tests the SPNs for the Service Account
.PARAMETER name
    Name of Service Account
.PARAMETER moduleID
    An optional ID of the module calling this function  
.NOTES
    ID FBP-AD-0004
#>
[CmdletBinding()]
Param(
    # name of Service Account
    [Parameter(Mandatory=$true)]
    [System.String]$name,

    # the identities type
    [Parameter(Mandatory=$true)]
    [System.String[]]$SPNs,

    # optional module ID
    [System.String]$moduleID
)
    
    if ($moduleID -eq "") { $moduleID = "N/A"}
    $obj = [TapResult]::New("FBP-AD-0004", $moduleID, "SPNs for Service Account are as expected")

    Write-Verbose "[FBP-AD-0004]: Search for Service Principle Name."
    $search = New-Object DirectoryServices.DirectorySearcher([ADSI]“”)
    $search.filter = "name=$name" 
    $result = $search.FindOne()

    $entry = $result.GetDirectoryEntry()
     
    $existingSPN = @()
    
    Write-Verbose "[FBP-AD-0004]: Extract Service Principal Names."
    foreach($spn in $entry.servicePrincipalName) { $existingSPN += $spn }

    Write-Verbose "[FBP-AD-0004]: Compare found SPNs with the default..."
    $compare = Compare-Object -ReferenceObject $SPNs -DifferenceObject $existingSPN

    if ($null -eq $compare) 
    {
        $obj.Status = $existingSPN
        $obj.Passed = 1
    }
    else 
    {
        $missing = @()
        $unexpected = @()
        $messageBag = "Additional info:" + [System.Environment]::NewLine
        $messageBag += "ID:[FBP-AD-0004]" + [System.Environment]::NewLine
        $messageBag += "Module ID: [$moduleID)]"

        foreach($inputObject in $compare)
        {
            if($inputObject.sideIndicator -eq "=>")
            {
                $unexpected += $inputObject.inputObject

                $msg = "Unexpected SPN for service account $name : $($inputObject.inputObject)" + [System.Environment]::NewLine
                $msg += $messageBag
                Write-EventLog -LogName "FBPRO-TAP" -Source "AD-TAP" -Message $msg -EventId 6 -EntryType Warning -Category 0 
            }
            elseif($inputObject.sideIndicator -eq "<=")
            {
                $missing += $inputObject.inputObject

                $msg = "Missing SPN for service account $name : $($inputObject.inputObject)" + [System.Environment]::NewLine
                $msg += $messageBag
                Write-EventLog -LogName "FBPRO-TAP" -Source "AD-TAP" -Message $msg -EventId 5 -EntryType Error -Category 0 
            }
        }

        if ($missing)
        {
            $obj.Status = "Missing SPN(s): $missing"+[System.Environment]::NewLine+"Unexpected SPN(s): $unexpected"
            $obj.Passed = 2 #Failed
        }
        elseif ($unexpected)
        {
            $obj.Status = "Unexpected SPN(s): $unexpected"
            $obj.Passed = 3 #Warning
        }
    }

    Write-Output $obj
}

function Test-ADSecurityGroupMember
{
<#
.Synopsis
   Checks, if only expected members are in the security group
.DESCRIPTION
   Checks, if only expected members are in the security group
.PARAMETER securityGroup
    The name of the security group
.PARAMETER members
    The members of the security group (their SAMAccountName)
.PARAMETER moduleID
    An optional ID of the module calling this function  
.NOTES
    ID FBP-AD-0005
#>
[CmdletBinding()]
Param(
    # name of security group
    [Parameter(Mandatory=$true)]
    [string]$securityGroup,

    # Members that should be in the security group
    [Parameter(Mandatory=$true)]
    [string[]]$members,
    
    [String]$moduleId
)

    if ($moduleID -eq "") { $moduleID = "N/A"}
    $obj = [TapResult]::New("FBP-AD-0005", $moduleID, "Security group members in group $securityGroup are correct")

    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[FBP-AD-0005]" + [System.Environment]::NewLine
    $messageBag += "Module ID: [$moduleID)]"

    try 
    {      
        $groupmembers = Get-ADGroupMember $securityGroup -Recursive | Select-Object -ExpandProperty SamAccountName

        $nl = [System.Environment]::NewLine

        $compare = Compare-Object -ReferenceObject $groupmembers -DifferenceObject $members -ErrorAction Stop
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
            $obj.Status = "Not listed members found ($unexpectedCounter): $nl$unexpected $nl Missing members ($missingCounter): $nl$missing"
            $obj.Passed = 2
            Write-LogFile -Path $LogPath -name $LogName -message "Not listed members found ($unexpectedCounter): $nl$unexpected $nl Missing members ($missingCounter): $nl $missing" -Level Error

            $msg = "Found unexpected member(s) ($unexpectedCounter) in security group $securityGroup : $nl$unexpected"+[System.Environment]::NewLine
            $msg += $messageBag
            Write-EventLog -LogName "FBPRO-TAP" -Source "AD-TAP" -Message $msg -EventId 9 -EntryType Error -Category 0 

            $msg = "Missing member(s) ($missingCounter) in security group $securityGroup : $nl$missing"+[System.Environment]::NewLine
            $msg += $messageBag
            Write-EventLog -LogName "FBPRO-TAP" -Source "AD-TAP" -Message $msg -EventId 8 -EntryType Warning -Category 0
        }
        elseif ($unexpected) 
        {
            $obj.Status = "Not listed members found ($unexpectedCounter): $nl$unexpected"
            $obj.Passed = 2
            Write-LogFile -Path $LogPath -name $LogName -message "Not listed members found ($unexpectedCounter): $unexpected" -Level Error  
            
            $msg = "Found unexpected member(s) ($unexpectedCounter) in security group $securityGroup : $nl$unexpected"+[System.Environment]::NewLine
            $msg += $messageBag
            Write-EventLog -LogName "FBPRO-TAP" -Source "AD-TAP" -Message $msg -EventId 9 -EntryType Error -Category 0 
        }
        elseif ($missing)
        {
            $obj.Status = "Missing members ($missingCounter): $nl $missing"
            $obj.Passed = 3 
            Write-LogFile -Path $LogPath -name $LogName -message "Missing members ($missingCounter): $missing" -Level Warning

            $msg = "Missing member(s) ($missingCounter) in security group $securityGroup : $nl$missing"+[System.Environment]::NewLine
            $msg += $messageBag
            Write-EventLog -LogName "FBPRO-TAP" -Source "AD-TAP" -Message $msg -EventId 8 -EntryType Warning -Category 0
        }
        else 
        {
            $obj.Status = "All correct"
            $obj.Passed = 1
        }
    }
    catch
    {
        $obj.Status = "An error occured while comparing actual / target state of security group."
        $obj.Passed = 4

        Write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error

        $msg = "An error occured while comparing actual / target state of security group."+[System.Environment]::NewLine
        $msg += $messageBag+[System.Environment]::NewLine
        $msg += $_.Exception
        Write-EventLog -LogName "FBPRO-TAP" -Source "AD-TAP" -Message $msg -EventId 7 -EntryType Error -Category 0
    }

    Write-Output $obj
}




# 2 Further test functions and 
# ------------------------ 
#
# Section for all "private" functions
#

<#
.Synopsis
    Tests a certain property for a given Active Directory user/service account.
.DESCRIPTION
    Tests a certain property for a given Active Directory user/service account. It takes SAMAccount name or SID to get informations from Active Directory.
    Therefore the Active Directory module must be installed on the system (or RSAT).
.PARAMETER TapResultObject
    An instance of a TapResultObject.
.PARAMETER identity
    Either the SAMAccountName or the SID of the service account depending on parameter type.
.PARAMETER type
    The tpye of the identity. Possible values are SID or SamAccountName.
.PARAMETER property
    The property to retrieve.
.PARAMETER propertyValue
    The expected value of the property. Could be a string, a boolean etc.
.EXAMPLE

#>
function Test-ADAccountProperty
{
[CmdletBinding()]
Param(
    # a Tap Result object
    [Parameter(Mandatory=$true)]
    [TapResult]$TapResultObject,
    
    # the identity depending on type (SamAccountName, SID)
    [Parameter(Mandatory=$true)]
    [System.String]$identity,

    # the identities type
    [ValidateSet('SamAccountName','Sid')]
    [Parameter(Mandatory=$true)]
    [System.String]$type,

    # property to check
    [ValidateSet('Enabled','PasswordExpired', 'PasswordNeverExpires', 'PasswordNotRequired')]
    [Parameter(Mandatory=$true)]
    [System.String]$property,

    # value of checked property (could be a string or boolean etc.)
    [Parameter(Mandatory=$true)]
    $propertyValue
)

    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[$($TapResultObject.ID)]" + [System.Environment]::NewLine
    $messageBag += "Module ID: [$($TapResultObject.moduleID)]"
     
    try
    {
        Write-Verbose "[$($TapResultObject.ID)]: Getting property information for identity $identity from Active Directory"

        $value = Get-ADUser -Filter {$type -eq $identity} -Properties * | Select-Object -ExpandProperty $property -ErrorAction Stop

        if ($null -eq $value)
        {
            $TapResultObject.Status = "Identity or property not found"
            $TapResultObject.Passed = 4   
            
            $msg = "Identity <$identity> or property <$property> not found." + [System.Environment]::NewLine
            $msg += $messageBag
              
            Write-EventLog -LogName "FBPRO-TAP" -Source "AD-TAP" -Message $msg -EventId 1 -EntryType Error -Category 0 
        } 

        else
        {                  
            Write-Verbose "[$($TapResultObject.ID)]: Checking property value..."

            if ($value -eq $propertyValue)
            {
                $TapResultObject.Status = $propertyValue
                $TapResultObject.Passed = 1
            }
            else
            {
                $TapResultObject.Status = "Missmatch: $value"
                $TapResultObject.Passed = 2
                
                $msg = "Unexpected value. Found $value for property $property, expected $propertyValue." + [System.Environment]::NewLine
                $msg += $messageBag
                Write-EventLog -LogName "FBPRO-TAP" -Source "AD-TAP" -Message $msg -EventId 2 -EntryType Error -Category 0    
            }
        }
    }

    catch [Microsoft.ActiveDirectory.Management.ADServerDownException]
    {
        $TapResultObject.Status = "Active Directory not reachable"
        $TapResultObject.Passed = 4

        $msg =  "Active Directory: Unable to contact the server. This may be because this server does not exist, it is currently down, or it does not have the Active Directory Web Services running." + [System.Environment]::NewLine
        $msg += $messageBag
        Write-EventLog -LogName "FBPRO-TAP" -Source "AD-TAP" -Message $msg -EventId 3 -EntryType Error -Category 0
    }

    # catch authentication exception
    catch [System.Security.Authentication.AuthenticationException]
    {
        $TapResultObject.Status = "Call to SSPI failed"
        $TapResultObject.Passed = 4

        $msg = "A call to SSPI (Security Support Provider Interface) failed." + [System.Environment]::NewLine
        $msg += $messageBag
        Write-EventLog -LogName "FBPRO-TAP" -Source "AD-TAP" -Message $msg -EventId 4 -EntryType Error -Category 0
    }

    # all other exceptions
    catch
    {
        $TapResultObject.Status = "Unknown error"
        $TapResultObject.Passed = 4

        Write-EventLog -LogName "FBPRO-TAP" -Source "AD-TAP" -Message $error[0] -EventId 5 -EntryType Error -Category 0
    }

    # return the changed TapResultObject
    return $TapResultObject
}