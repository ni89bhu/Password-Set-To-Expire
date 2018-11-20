#######################################################################################################################################
#<Description>                                                                                                                        #
#This script will write co-relate relevent details from 4738 alert's csv outputs and generate an event if password was set to never   #
#expire for usrs and was not reverted back within 24 Hrs. Script will also truncate entries in output files later than 48 hours.      # 
#                                                                                                                                     #
#CreatedBy:kumarnitesh@eventtracker.com                                                                                               #
#Created On:11/20/18                                                                                                                  #
#######################################################################################################################################
#######################################################################################################################################
$etpath = (Get-ItemProperty -Path 'registry::hklm\SOFTWARE\Wow6432Node\Prism Microsystems\EventTracker\Manager').INSTALLPATH
$scriptdir = split-path $SCRIPT:MyInvocation.MyCommand.Path -parent
$db1 = Import-Csv "$scriptdir\Data\pwexptrue.csv"
$db2 = Import-Csv "$scriptdir\Data\pwexpfalse.csv"

#######################################################################################################################################
foreach ($1 in $Db1){
$umatch = $db2 |Where-Object {($1.UserChanged -eq $_.UserChanged) -and ($1.DomainChanged -eq $_.DomainChanged) -and ((([datetime]$1.eventtime - [datetime]$_.eventtime)).TotalHours -le 24)}
If (!($umatch)) {
$uc = ($1.UserChanged)
$dc = ($1.DomainChanged)
$et = ($1.EventTime)
& "$etpath\ScheduledActionScripts\sendtrap.exe" ET $env:COMPUTERNAME $computer 3 2 "EventTracker" 0 8027 "Password expiration of user $uc in domain $dc was set to never expire on $et and not reverted back within 24 Hrs." N/A N/A " " 14505
}}

#######################################################################################################################################
$db1 | Where-Object {($_.eventtime -gt (get-date (get-date).AddDays(-2) -Format G))} | export-csv Import-Csv "$scriptdir\Data\pwexptrue.csv" -NoTypeInformation
$db2 | Where-Object {($_.eventtime -gt (get-date (get-date).AddDays(-2) -Format G))} | export-csv Import-Csv "$scriptdir\Data\pwexpfalse.csv" -NoTypeInformation

#######################################################################################################################################
#######################################################################################################################################