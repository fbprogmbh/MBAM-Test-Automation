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
    Date:             05/29/2018
    Last change:      08/09/2018
    Version:          1.1
    State:            Approved
#>

<# 
    Module for testing Windows PKI related issues.

#>

Using module TapResultClass

#region Imports
Import-Module LogFileModule -ErrorAction SilentlyContinue

# Load settings from setting file
$pkiExtensionModulePath = (Get-Module -ListAvailable PkiExtensionModule).Path
$baseDir = (Get-Item $pkiExtensionModulePath).Directory.Parent.Fullname+"\Settings"
Import-LocalizedData -FileName Settings.psd1 -BaseDirectory $baseDir -BindingVariable "ConfigFile"
#endregion

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


function Test-PkiCertificateValid
{
<#
.Synopsis
    Verifies that the certificate of the web page is valid.
.DESCRIPTION
    Verifies that the certificate of the web page is valid. 
    This is done by checking the revoke status of the certificate and if DNS name in certificate matches the MBAM hostname.
    The optional moduleID if the test is called by another TAP module
.PARAMETER hostname
    The CN of the certificate
.PARAMETER thumbprint
    The thumbprint of the certificate
.PARAMETER moduleID
    The optional moduleID if the test is called by another TAP module
.NOTES
    ID  FBP-PKI-0001
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [String]$hostname,

    [Parameter(Mandatory=$true)]
    [String]$thumbprint,

    [String]$moduleID 
)

    if (($null -eq $moduleID) -or ($moduleID -eq "") ) { $moduleID = "N/A" }
    
    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[FBP-PKI-0001]" + [System.Environment]::NewLine
    $messageBag += "Module ID: $moduleID"
    
    $obj = [TapResult]::New("FBP-PKI-0001", $moduleID, "The used certificate is valid")
    
    # save PS location to return later
    $location = Get-Location

    try 
    {

        # Get a certificate object of correspondingly thumbprint
        Set-Location Cert:\
        $certificate = Get-ChildItem -Recurse | Where-Object Thumbprint -EQ $thumbprint

        # Check validation of certificate
        if(Test-Certificate -DNSName $hostname -cert $certificate -ErrorAction Stop)
        {
            $obj.Status = "Certificate is valid"
            $obj.Passed = 1
        }
        else
        {
            $obj.Status = "Certificate not valid"
            $obj.Passed = 2
        }

            
    }
    catch
    { 
        $obj.Passed = 4

        # Create error message
        $e = $_.Exception.toString()
        $e += "; " + $_.ScriptStackTrace.toString()

        # Check for specific error messages
        # Certificate is revoked 
        if($msg -like "*CRYPT_E_REVOKED*")
        {
            $obj.Status = "Certificate is revoked"

            $msg = "Certificate with tumbprint $thumbprint is revoked"+[System.Environment]::NewLine
            $msg += $messageBag
            Write-EventLog -LogName "FBPRO-TAP" -Source "PKI-TAP" -Message $msg -EventId 1 -EntryType Warning -Category 0
        }
        # DNS name of certificate does not match the hostname
        elseif ($msg -like "*CERT_E_CN_NO_MATCH*")
        {
            $obj.Status= "CN-Name of certificate does not match"

            $msg = "CN-Name of certificate with tumbprint $thumbprint does not match"+[System.Environment]::NewLine
            $msg += $messageBag
            Write-EventLog -LogName "FBPRO-TAP" -Source "PKI-TAP" -Message $msg -EventId 2 -EntryType Warning -Category 0
        }
        # all other errors
        else
        {
            $obj.Status = "An error occurred, see logfile for more infos"

            $msg = "Error checking certificate state"+[System.Environment]::NewLine
            $msg += $messageBag+[System.Environment]::NewLine
            $msg += $e
            Write-EventLog -LogName "FBPRO-TAP" -Source "PKI-TAP" -Message $msg -EventId 3 -EntryType Error -Category 0
        }

        # log error
        write-LogFile -Path $LogPath -name $LogName -message $e -Level Error
    }

    #reset location 
    Set-Location $location

    Write-Output $obj
}

function Test-PkiCertificateExpirationDate
{
<#
.Synopsis
    Checks, if the certificate is not expired.
.DESCRIPTION
    Checks, if the certificate is not expired.
.PARAMETER thumbprint
    
.PARAMETER moduleID
    The optional moduleID if the test is called by another TAP module
.NOTES
    ID  FBP-PKI-0002
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [String]$thumbprint,

    [String]$moduleID 
)

    if (($null -eq $moduleID) -or ($moduleID -eq "") ) { $moduleID = "N/A" }
    
    $messageBag = "Additional info:" + [System.Environment]::NewLine
    $messageBag += "ID:[FBP-PKI-0002]" + [System.Environment]::NewLine
    $messageBag += "Module ID: $moduleID"
    
    $obj = [TapResult]::New("FBP-PKI-0002", $moduleID, "Certificate expiration date not reached")

    try 
    {
        $certificate = Get-ChildItem "Cert:\" -Recurse | Where-Object Thumbprint -EQ $thumbprint

        $days = ($certificate.NotAfter.Date - (Get-Date).Date).Days
       
        if (($days -le $ConfigFile.Settings.CertificateExpiresWarning) -and ($days -ge 0))
        {
            $obj.Status = "Certificate expires in $days days"
            $obj. Passed = 3

            $msg = "Certificate with thumbprint $thumbprint expires in $days days"+[System.Environment]::NewLine
            $msg += $messageBag
            Write-EventLog -LogName "FBPRO-TAP" -Source "PKI-TAP" -Message $msg -EventId 4 -EntryType Warning -Category 0
        }
        elseif ($days -lt 0)
        {
            $obj.Status = "Certificate expired"
            $obj.Passed = 2

            $msg = "Certificate with thumbprint $thumbprint is expired"+[System.Environment]::NewLine
            $msg += $messageBag
            Write-EventLog -LogName "FBPRO-TAP" -Source "PKI-TAP" -Message $msg -EventId 5 -EntryType Error -Category 0
        }
        else 
        {
            $obj.Status = "Certificate not expired"
            $obj.Passed = 1
        }
    }
    catch
    {
        # log error
        $e = $_.Exception.toString()
        $e += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $e -Level Error
    }

    Write-Output $obj
}