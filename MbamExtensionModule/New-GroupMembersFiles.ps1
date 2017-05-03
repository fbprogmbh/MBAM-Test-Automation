<#
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

    Author(s):        Dennis Esly 
    Date:             03/01/2017
    Last change:      05/02/2017
    Version:          1.0

#>

if( (Get-Module -List ActiveDirectory) -and !(Get-Module ActiveDirectory))
{
    import-Module ActiveDirectory

    try 
    {
        $path = (Get-Module -ListAvailable MbamExtensionModule).Path
        $path = $path.Substring(0,$path.LastIndexOf('\'))

        $AdvHelpDesk = Get-MbamWebApplication -AdministrationPortal | select -ExpandProperty AdvancedHelpdeskAccessGroup -ErrorAction Stop;
        $AdvHelpDesk = $AdvHelpDesk.Remove(0, $AdvHelpDesk.IndexOf('\')+1)
    
        $HelpDesk = Get-MbamWebApplication -AdministrationPortal | select -ExpandProperty HelpdeskAccessGroup -ErrorAction Stop;
        $HelpDesk = $HelpDesk.Remove(0, $HelpDesk.IndexOf('\')+1)
    
        $ReportsRO = Get-MbamWebApplication -AdministrationPortal | select -ExpandProperty ReportsReadOnlyAccessGroup -ErrorAction Stop;
        $ReportsRO = $ReportsRO.Remove(0, $ReportsRO.IndexOf('\')+1)

        Get-ADGroupMember $AdvHelpDesk -Recursive | select -ExpandProperty SamAccountName > $path\AdvHelpDeskMembers.txt
        Get-ADGroupMember $HelpDesk -Recursive | select -ExpandProperty SamAccountName > $path\HelpDeskMembers.txt
        Get-ADGroupMember $ReportsRO -Recursive | select -ExpandProperty SamAccountName > $path\ReportsROMembers.txt
    }    
    catch
    {
        Write-Error $_.Exception.Message
    }
}
else
{
    Write-Warning "Necessary Module ActiveDirectory missing. Try cmdlet 'Add-WindowsFeature RSAT-AD-PowerShell' or use ServerManager to add feature!" 
}
    