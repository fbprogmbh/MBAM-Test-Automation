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
    Date:             04/26/2018
    Last change:      05/02/2018
    Version:          0.1
    State:            Draft
#>

Class TapResult
{
    [String]$ID
    [String]$moduleID
    [String]$Task
    [String]$Status
    [PassedStatus]$Passed

    # Parameterless Constructor
    TapResult ()
    {      
        $this.ID = ""
        $this.moduleID = ""
        $this.Task = ""
        $this.Status = "Not started"
        $this.Passed = "Error"
    }

    # Constructor
    TapResult ([String]$ID, [String]$Task)
    {
        $this.ID = $ID
        $this.moduleID = "N/A"
        $this.Task = $Task
        $this.Status = "Not started"
        $this.Passed = "Error"
    }

    # Constructor
    TapResult ([String]$ID, [String]$moduleID, [String]$Task)
    {
        $this.ID = $ID
        $this.moduleID = $moduleID
        $this.Task = $Task
        $this.Status = "Not started"
        $this.Passed = "Error"
    }
}


Enum PassedStatus
{
    Passed = 1
    Failed = 2
    Warning = 3
    Error = 4
}