# MBAM Test Automation Package Version 2 #

## Overview ##
The MBAM Test Automation Package gives you the ability to get an overview about the availability and the security status of your Microsoft Bitlocker Administration and Monitoring (MBAM) system.
You can easily create HTML-reports, even on a regulary basis. Or test specific components and security issues of your system.

For more information about the many functions inside the package go to the *documentation* folder inside the package.

Revised version 2 comes with some improvements in usability and speed as well as new features like event logging.

## Getting started ##

### Requirements ###
* MBAM TAP version 2 uses PowerShell classes. For the best MBAM TAP experience you should use at least the Windows Management Framework 5.0 (WMF 5.0) which includes PowerShell Version 5. If you are running an older version of PowerShell you can download the WMF package for your operating system at https://www.microsoft.com/en-us/download/details.aspx?id=54616
We recommend to use WMF 5.1.


* Download or clone the package
* Adjust your execution policy to at least remoteSigned (the scripts are not digitally signed yet)

```powershell
	Set-ExecutionPolicy RemoteSigned -scope CurrentUser
```

* Copy/put the following folders in a PowerShell default load path to get the modules and classes automatically loaded.  

  * MBAMExtensionModule
  * ADExtensionModule
  * PkiExtensionModule
  * WinSrvExtensionModule
  * LogFileModule
  * Classes

A default load path could be e.g. the path in your user profile under *"userprofile"\Documents\WindowsPowerShell\Modules* (if it does not exists, you have to create it) or the new location under  *C:\Program Files\WindowsPowerShell\Modules*.
For a easy start you can use the **Install-MbamExtensionModule.ps1** script to add the current of your cloned/unzipped package location into the PowerShell module path environment variable.
* For the server side report run the PowerShell scripts *New-GroupMembersFiles.ps1* and *New-LocalAdminsFile.ps1* inside the folder MbamExtensionModule once to create  files which will contain the users of the MBAM security groups as well as a file with all local admins. 
* To use the new feature of event logging, a new application log must be registered as well as some event sources. For this execute the script *New-FBProEventLogs.ps1* inside the *scripts* folder, it will do the work.

### Settings.psd1 ###
In order to use some functions for the  report adjust some settings in the file *Settings.psd1* which is located inside the MbamExtensionModule folder

* To use the email reporting function first add your email settings

```powershell
Email = @{
            SMTPServer = "smtp.example.com"
            SMTPPort = 25
            MailTo = "mbam@example.com"
            MailFrom = "MBAM Error Reporting"
            Encoding = "UTF8"
            User = "mbamtap@example.com"
            PasswordFile = ""
        }
```

* For testing the certificate which is used by MBAM add your certificate thumbprint 

```powershell
# Expiration date warning starts <CertificateExpiresWarning> days before expiration
CertificateExpiresWarning = 60
        
# Mbam certificate thumbprint   
CertificateThumbprint = "‎fb23b9bedc426ebd7d76c11a6170d7adbebbf"
```
* Its possibile to add a logo to your report. You can change the Base64 string for the variable *logo* or exchange it to an URI. We recommend to use a Base64 string.




## Usage ##

### HTML reports ###
You will find two scripts within the package which will give you the possibility to create HTML server reports.
The script *Get-CompleteServerStatus.ps1* creates a report with a bunch of testresults and additional update or login history views. Depending on the size of your MBAM environment, this test could take some time.
That is why the package also includes another script called *Get-QuickServerStatus.ps1* which will not create the history views to get a report faster for occasionally manual testing, e.g. after a MBAM update.

Before running the scripts open them and look at the section *Configuration* after the license block. In order to work properly you may have to adjust some variables like the MBAM version your server is running or the path where the reports will be created.

```powershell
$mbamVersion = "2.5.1135.0"
```

```powershell
$reportHtmlTitle = "FB Pro GmbH - MBAM-Server report " + (Get-Date -UFormat "%Y%m%d_%H%M") 
```

The same applies for the script *Get-CompleteClientStatus.ps1* for creating a HTML-report on a client. Set your MBAM Client Agent version, adjust the save path for your reports and you are ready to go. Remember you have to do the same as you did for the server reports, which means copy the package to the client, install the module and set your execution policy.   

### Build your own ###

If you have no use or just do not like the html report scripts, you can build and run your own script and export or save it to any format you like. To do so you find a bunch of *Test-* functions to use in your script and suit your need.

E.g.

```powershell
PS C:\> Test-MbamServerVersion -version "2.5.1135.0"

ID       : FBP-MBAM-0038
moduleID : TC-MBAM-0032
Task     : The MBAM Server main version number is correct
Status   : Version correct, installed version is 2.5.1135.0
Passed   : Passed
```
