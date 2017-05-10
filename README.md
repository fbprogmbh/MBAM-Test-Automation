# MBAM Test Automation Package #

## Overview ##
The MBAM Test Automation Package gives you the ability to get an overview about the availability and the security status of your Microsoft Bitlocker Administration and Monitoring (MBAM) system.
You can easily create HTML-reports, even on a regulary basis. Or test specific components and security issues of your system.

For more information about the many functions inside the package go to the *documentation* folder inside the package.


## Getting started ##

* Download or clone the package
* The scripts are not digitally signed yet, so you have to set your execution policy, for example to remoteSigned. 

```powershell
	Set-ExecutionPolicy RemoteSigned
```

* Copy/put the *MbamExtensionModule* folder in a PowerShell default load path to get the module automatically loaded. That could be e.g. the path in your user profile under *"userprofile"\Documents\WindowsPowerShell\Modules*. If it does not exists, you have to create it.
Or simply use the **Install-MbamExtensionModule.ps1** script to add the current location into the PowerShell module path environment variable.
* For the server side report run the PowersShell scripts *New-GroupMembersFiles.ps1* and *New-LocalAdminsFile.ps1* inside the folder MbamExtensionModule once to create  files which will contain the users of the MBAM security groups as well as a file with all local admins. 

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
$mbamVersion = "2.5.1133.0"
```

```powershell
$reportHtmlTitle = "FB Pro GmbH - MBAM-Server report " + (Get-Date -UFormat "%Y%m%d_%H%M") 
```

### Build your own ###

If you have no use or just do not like the html report scripts, you can build and run your own script and export or save it to any format you like. To do so you find a bunch of *Test-* functions to use in your script and suit your need.

E.g.

```powershell
PS C:\Users\Administrator.MBAM> Test-MbamServerVersion25 -version 2.5.1133.0

Name             Task                     Status                                           Passed
----             ----                     ------                                           ------
TC-Mbam-0032     Mbam-server version      Version correct, installed version is 2.5.1...   true  
```
