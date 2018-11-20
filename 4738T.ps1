#######################################################################################################################################
#<Description>                                                                                                                        #
#This script will write relevent details from 4738(Account Expires:<never>) alert to a csv file for correlation through remidial      #
#action.                                                                                                                              #
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
$db = "$scriptdir\Data\pwexptrue.csv"
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
	Security ID:		S-1-5-18
	Account Name:		MIS4$
	Account Domain:		PSCOMIS
	Logon ID:		0x3E7

Target Account:
	Security ID:		S-1-5-21-1400892752-2889334953-2262572570-500
	Account Name:		Administrator
	Account Domain:		MIS4

Changed Attributes:
	SAM Account Name:	Administrator
	Display Name:		<value not set>
	User Principal Name:	-
	Home Directory:		<value not set>
	Home Drive:		<value not set>
	Script Path:		<value not set>
	Profile Path:		<value not set>
	User Workstations:	<value not set>
	Password Last Set:	11/19/2018 7:54:39 AM
	Account Expires:		<never>
	Primary Group ID:	513
	AllowedToDelegateTo:	-
	Old UAC Value:		0x10
	New UAC Value:		0x10
	User Account Control:	-
	User Parameters:	-
	SID History:		-
	Logon Hours:		All

Additional Information:
	Privileges:		-

<EventData><Data Name=''Dummy''>-</Data><Data Name=''TargetUserName''>Administrator</Data><Data Name=''TargetDomainName''>MIS4</Data><Data Name=''TargetSid''>S-1-5-21-1400892752-2889334953-2262572570-500</Data><Data Name=''SubjectUserSid''>S-1-5-18</Data><Data Name=''SubjectUserName''>MIS4$</Data><Data Name=''SubjectDomainName''>PSCOMIS</Data><Data Name=''SubjectLogonId''>0x3e7</Data><Data Name=''PrivilegeList''>-</Data><Data Name=''SamAccountName''>Administrator</Data><Data Name=''DisplayName''><value not set></Data><Data Name=''UserPrincipalName''>-</Data><Data Name=''HomeDirectory''><value not set></Data><Data Name=''HomePath''><value not set></Data><Data Name=''ScriptPath''><value not set></Data><Data Name=''ProfilePath''><value not set></Data><Data Name=''UserWorkstations''><value not set></Data><Data Name=''PasswordLastSet''>11/19/2018 7:54:39 AM</Data><Data Name=''AccountExpires''><never></Data><Data Name=''PrimaryGroupId''>513</Data><Data Name=''AllowedToDelegateTo''>-</Data><Data Name=''OldUacValue''>0x10</Data><Data Name=''NewUacValue''>0x10</Data><Data Name=''UserAccountControl''>-</Data><Data Name=''UserParameters''>-</Data><Data Name=''SidHistory''>-</Data><Data Name=''LogonHours''>All</Data></EventData>'