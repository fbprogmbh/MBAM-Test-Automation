# Create FB Pro custom event logs

New-EventLog -LogName "FBPRO-TAP" -Source "AD-TAP" -Verbose
New-EventLog -LogName "FBPRO-TAP" -Source "MBAM-TAP" -Verbose
New-EventLog -LogName "FBPRO-TAP" -Source "SharePoint-TAP" -Verbose
New-EventLog -Logname "FBPRO-TAP" -Source "WinSrv-TAP" -Verbose
New-EventLog -Logname "FBPRO-TAP" -Source "PKI-TAP" -Verbose