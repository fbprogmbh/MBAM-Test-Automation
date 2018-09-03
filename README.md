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
* For the server side report run the PowerShell scripts *New-GroupMembersFiles.ps1* and *New-LocalAdminsFile.ps1* inside the folder MbamExtensionModule once to create files which contain the users of the MBAM security groups as well as a file with all local admins. 
* To use the new feature of event logging, a new application log must be registered as well as some event sources. For this execute the script *New-FBProEventLogs.ps1* inside the *scripts* folder, it will do the work.

### Settings ###
Inside the new Settings folder you find the file *Settings.psd1*. This file contains some settings for the creation of the report as well as some set points like the MBAM server version. See explanations below:

* MBAM Server version
```powershell
...
 Mbam = @{
            Server = @{
    		Version = "2.5.1135.0"
...
```

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
Settings = @{
        Mbam = @{
            Server = @{
                # Mbam certificate thumbprint   
                CertificateThumbprint = "fb2493b5bedc426ebd7d76c939a6170d7adbebbf"
		...
```

* Set the MBAM service account name as well as the used MBAM security groups
```powershell
...
Mbam = @{
    Server = @{
	# Mbam Service Account (WebService Application Pool Account
	ServiceAccount = "MBAMSvcAcc"
	# MBAM Advanced Help Desk Security Group (without domain)
	AdvHelpDesk = "MBAMAdvHelpDesk"
	# MBAM Help Desk Security Group (without domain)
	HelpDesk = "MBAMHelpDesk"
	# MBAM Reports only Security Group (without domain)
	ReportGroup = "MBAMReport"
...
```

* Its possibile to add a logo to your report. You can change the Base64 string for the variable *logo* or exchange it to an URI. We recommend to use a Base64 string.

## Usage ##

### HTML server reports ###
To create a server html report, run the script *Get-CompleteServerStatus.ps1* within an elevated PowerShell console.
Please remember to adjust your settings inside the *settings.psd1* file as describe above first.

### HTML client reports ###
Before running the client script *Get-CompleteClientStatus.ps1* open the script and look at the section *Configuration* after the license block. In order to work properly you may have to adjust some variables like the MBAM version your client agent is running or the path where the reports will be created.


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
