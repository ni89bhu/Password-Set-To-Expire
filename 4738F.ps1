#######################################################################################################################################
#<Description>                                                                                                                        #
#This script will write relevent details from 4738(Account Expires:-) alert to a csv file for correlation through remidial action.    #
#                                                                                                                                     #
#CreatedBy:kumarnitesh@eventtracker.com                                                                                               #
#Created On:11/20/18                                                                                                                  #
#######################################################################################################################################
#######################################################################################################################################
param (
[string]$Event_log_type,
[string]$log_type,
[string]$computer,
[string]$source,
[string]$category,
[string]$event_id,
[string]$user,
[string]$description
)

$scriptdir = split-path $SCRIPT:MyInvocation.MyCommand.Path -parent
New-Item -ItemType Directory -Force -Path "$scriptdir\Data"
$db = "$scriptdir\Data\pwexpfalse.csv"
$et = get-date -Format G

#######################################################################################################################################
$regex = '(?s)Target Account\:.*?Account Name\:(.*?)Account Domain\:(.*?)Changed Attributes\:.*?Account Expires\:(.*?)Primary Group ID\:'
Filter Extract
{
$_ -match $regex > $null
[PSCustomObject]@{
EventTime = $et
UserChanged =  $Matches[1].trim()
DomainChanged = $Matches[2].trim()
ExpireSettings = switch ($Matches[3].trim()) {
    '-' {"False"}
    '<never>' {"True"}
}
}}

$event = ($description | Extract) | Select-Object -Property EventTime,UserChanged,DomainChanged,ExpireSettings
$event | Export-csv -Path $db -Append -NoTypeInformation

#######################################################################################################################################
#######################################################################################################################################

$description = 'A user account was changed.

Subject:
	Security ID:		S-1-5-7
	Account Name:		ANONYMOUS LOGON
	Account Domain:		NT AUTHORITY
	Logon ID:		0x3E6

Target Account:
	Security ID:		S-1-5-21-685956784-2436697818-2600286751-5125
	Account Name:		cransom
	Account Domain:		WKRCTRLS

Changed Attributes:
	SAM Account Name:	-
	Display Name:		-
	User Principal Name:	-
	Home Directory:		-
	Home Drive:		-
	Script Path:		-
	Profile Path:		-
	User Workstations:	-
	Password Last Set:	11/19/2018 7:43:41 AM
	Account Expires:		-
	Primary Group ID:	-
	AllowedToDelegateTo:	-
	Old UAC Value:		-
	New UAC Value:		-
	User Account Control:	-
	User Parameters:	-
	SID History:		-
	Logon Hours:		-

Additional Information:
	Privileges:		-

<EventData><Data Name=''Dummy''>-</Data><Data Name=''TargetUserName''>cransom</Data><Data Name=''TargetDomainName''>WKRCTRLS</Data><Data Name=''TargetSid''>S-1-5-21-685956784-2436697818-2600286751-5125</Data><Data Name=''SubjectUserSid''>S-1-5-7</Data><Data Name=''SubjectUserName''>ANONYMOUS LOGON</Data><Data Name=''SubjectDomainName''>NT AUTHORITY</Data><Data Name=''SubjectLogonId''>0x3e6</Data><Data Name=''PrivilegeList''>-</Data><Data Name=''SamAccountName''>-</Data><Data Name=''DisplayName''>-</Data><Data Name=''UserPrincipalName''>-</Data><Data Name=''HomeDirectory''>-</Data><Data Name=''HomePath''>-</Data><Data Name=''ScriptPath''>-</Data><Data Name=''ProfilePath''>-</Data><Data Name=''UserWorkstations''>-</Data><Data Name=''PasswordLastSet''>11/19/2018 7:43:41 AM</Data><Data Name=''AccountExpires''>-</Data><Data Name=''PrimaryGroupId''>-</Data><Data Name=''AllowedToDelegateTo''>-</Data><Data Name=''OldUacValue''>-</Data><Data Name=''NewUacValue''>-</Data><Data Name=''UserAccountControl''>-</Data><Data Name=''UserParameters''>-</Data><Data Name=''SidHistory''>-</Data><Data Name=''LogonHours''>-</Data></EventData>'