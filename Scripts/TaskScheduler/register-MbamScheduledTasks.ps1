﻿<#
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
    FB Pro GmbH | register-MbamScheduleTasks.ps1

    Author:        Dennis Esly
    Date:          02/27/2017
    Last change:   05/02/2017
    Version:       1.0

    Registers a scheduled task, which daily execute a PowerShell script to create
    a MBAM server status report. 
    The task is saved in a MBAM folder in task manager, which is created if it does not exists.
#>

# A daily task is registered in the task scheduler. This is the time the task is scheduled to run.
Param(
    [string]$startTime = "7am"  
)

$taskAction = New-ScheduledTaskAction –Execute "Powershell.exe" -Argument $PSScriptRoot"\Get-CompleteMbamServerReport.ps1"
$taskTrigger = New-ScheduledTaskTrigger -Daily -At $startTime
$taskPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest 
$taskSettingsSet = New-ScheduledTaskSettingsSet

$task = New-ScheduledTask -Action $taskAction -Principal $taskPrincipal -Trigger $taskTrigger -Settings $taskSettingsSet
$task.Author = "FB Pro GmbH"
$task.Description = "Creates a MBAM server status report on a daily basis. Reports are saved as html files in the report directory specified in the settings file. Optionally the test results are saved as xml objects too."

Register-ScheduledTask "MBAM-Server daily test" -TaskPath "\MBAM" -InputObject $task