# TASK SCHEDULER #

To run the MBAM report script on a daily basis, you can add a new scheduled task to the task scheduler. 
For a quick start use the script *Register-MbamScheduledTask.ps1*. It will create a new folder MBAM inside the task 
scheduler with a new daily task which will run the MBAM report script at 7 am.
This task will run with the NT AUTHORITY\SYSTEM account.

You can edit the start time for the task inside the script, pass it as parameter or edit it in the task scheduler management console later on.

**Attention**
Do not move the script to another location before running as it will use the script root to register the script *Get-CompleteServerReport.ps1*
