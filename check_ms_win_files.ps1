# Script name:  check_ms_win_files.ps1
# Version:      v1.00.0000
# Created on:   26/10/2018
# Author:       Thierry Bissler
# Purpose:      Checks Microsoft Windows files presence and size.
# Thanks:       Largely based on check_ms_win_tasks.ps1, see https://github.com/willemdh/check_ms_win_tasks
# On Github:    https://github.com/Thibibi/check_ms_win_files
# Copyright:
#   This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published
#   by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. This program is distributed 
#   in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A 
#   PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU General Public 
#   License along with this program.  If not, see <http://www.gnu.org/licenses/>.

#Requires -Version 2.0
#Add-Content test.log $Args
$DebugPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'

$Struct = New-Object -TypeName PSObject -Property @{
	ExitCode = [int]3
	File = [string]''
	WarningThreshold =  [int]0
	WarningReverse = [bool]$False
	CriticalThreshold =  [int]0
	CriticalReverse = [bool]$False
	AlertOnExist = [bool]$False
	AlertOnNotExist = [bool]$False
	OutputString = [string]'Unknown: Error processing, no data returned.'              
}

#region Functions
Function Write-Log {
	Param (
		[parameter(Mandatory=$True,HelpMessage='Log output')][string]$Log,
		[parameter(Mandatory=$True,HelpMessage='Log severity')][ValidateSet('Debug', 'Info', 'Warning', 'Error', 'Unknown')][string]$Severity,
		[parameter(Mandatory=$True,HelpMessage='Log message')][string]$Message
	)
	$Now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss,fff'
	$LocalScriptName = Split-Path -Path $myInvocation.ScriptName -Leaf
	If ( $Log -eq 'Verbose' ) {
		Write-Verbose -Message ('{0}: {1}: {2}: {3}' -f $Now, $LocalScriptName, $Severity, $Message)
	} ElseIf ( $Log -eq 'Debug' ) {
		Write-Debug -Message ('{0}: {1}: {2}: {3}' -f $Now, $LocalScriptName, $Severity, $Message)
	} ElseIf ( $Log -eq 'Output' ) {
		Write-Host ('{0}: {1}: {2}: {3}' -f $Now, $LocalScriptName, $Severity, $Message)
	} ElseIf ( $Log -match '^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])(?::(?<port>\d+))$' -or $Log -match '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$' ) {
		$IpOrHost = $log.Split(':')[0]
		$Port = $log.Split(':')[1]
		If ( $IpOrHost -match '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$' ) {
			$Ip = $IpOrHost
		} Else {
			$Ip = [Net.Dns]::GetHostAddresses($IpOrHost)[0].IPAddressToString
		}
		Try {
			$LocalHostname = ([Net.Dns]::GetHostByName((& "$env:windir\system32\hostname.exe")).HostName).tolower()
			$JsonObject = (New-Object -TypeName PSObject | 
				Add-Member -PassThru -NotePropertyName NoteProperty -NotePropertyValue logsource -InputObject $LocalHostname | 
				Add-Member -PassThru -NotePropertyName NoteProperty -NotePropertyValue hostname -InputObject $LocalHostname | 
				Add-Member -PassThru -NotePropertyName NoteProperty -NotePropertyValue scriptname -InputObject $LocalScriptName | 
				Add-Member -PassThru -NotePropertyName NoteProperty -NotePropertyValue logtime -InputObject $Now | 
				Add-Member -PassThru -NotePropertyName NoteProperty -NotePropertyValue severity_label -InputObject $Severity | 
				Add-Member -PassThru -NotePropertyName NoteProperty -NotePropertyValue message -InputObject $Message ) 
			If ( $psversiontable.psversion.major -ge 3 ) {
				$JsonString = $JsonObject | ConvertTo-Json
				$JsonString = $JsonString -replace "`n",' ' -replace "`r",' '
			} Else {
				$JsonString = $JsonObject | ConvertTo-Json2
			}               
			$Socket = New-Object -TypeName System.Net.Sockets.TCPClient -ArgumentList ($Ip,$Port) 
			$Stream = $Socket.GetStream() 
			$Writer = New-Object -TypeName System.IO.StreamWriter -ArgumentList ($Stream)
			$Writer.WriteLine($JsonString)
			$Writer.Flush()
			$Stream.Close()
			$Socket.Close()
		}
		Catch {
			Write-Host ("{0}: {1}: Error: Something went wrong while trying to send message to logserver `"{2}`"." -f $Now, $LocalScriptName, $Log)
		}
		Write-Verbose -Message ('{0}: {1}: {2}: Ip: {3} Port: {4} JsonString: {5}' -f $Now, $LocalScriptName, $Severity, $Ip, $Port, $JsonString)
	} ElseIf ($Log -match '^((([a-zA-Z]:)|(\\{2}\w+)|(\\{2}(?:(?:25[0-5]|2[0-4]\d|[01]\d\d|\d?\d)(?(?=\.?\d)\.)){4}))(\\(\w[\w ]*))*)') {
		If (Test-Path -Path $Log -pathType container){
		  Write-Host ('{0}: {1}: Error: Passed Path is a directory. Please provide a file.' -f $Now, $LocalScriptName)
		  Exit 1
		} ElseIf (!(Test-Path -Path $Log)) {
			Try {
				$Null = New-Item -Path $Log -ItemType file -Force	
			} 
			Catch { 
				$Now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss,fff'
				Write-Host ("{0}: {1}: Error: Write-Log was unable to find or create the path `"{2}`". Please debug.." -f $Now, $LocalScriptName, $Log)
				exit 1
			}
		}
		Try {
		  ('{0}: {1}: {2}: {3}' -f $Now, $LocalScriptName, $Severity, $Message) | Out-File -filepath $Log -Append   
		}
		Catch {
		  Write-Host ("{0}: {1}: Error: Something went wrong while writing to file `"{2}`". It might be locked." -f $Now, $LocalScriptName, $Log)
		}
	}
}

Function Initialize-Args {
	Param ( 
		[Parameter(Mandatory=$True,HelpMessage='Argument list')]$Args
	)
	Try {
		For ( $i = 0; $i -lt $Args.count; $i++ ) { 
			$CurrentArg = $Args[$i].ToString()
			If ($i -lt $Args.Count-1) {
				$Value = $Args[$i+1];
				If ($Value.Count -ge 2) {
					ForEach ($Item in $Value) {
						$Null = Test-Strings -String $Item
					}
				} Else {
					$Value = $Args[$i+1];
					$Null = Test-Strings -String $Value
				}
			} Else {
				$Value = ''
			}
			Switch -regex <#-casesensitive#> ($CurrentArg) {
				'^(-F|--File)$' {
					<# Careful, backslashes \ have been transformed to slashes / by the
					URL, but in order to keep coherence with local execution, we accept
					both in the regex. Subsequent code works with both notations. #>
					Add-Type -AssemblyName System.Web
					$value = [System.Web.HttpUtility]::HtmlDecode($value)
#					If ($value -match '^(?<quote>['']?)(?<Filename>(?:[A-Za-z]\:)(?:[\/\\][A-Za-z0-9áàâäãåçéèêëíìîïñóòôöõúùûüýÿæœÁÀÂÄÃÅÇÉÈÊËÍÌÎÏÑÓÒÔÖÕÚÙÛÜÝŸÆŒ&_\- \.,'']+[^''])+)\k<quote>$') {
					If ($value -match '^(?<quote>['']?)(?<Filename>(?:[A-Za-z]\:)(?:[\/\\][A-Za-z0-9&_\- \.,'']+[^''])+)\k<quote>$') {
						$Struct.File = $matches['filename']
					} Else {
						Throw ('Invalid filename {0}.' -f $value)
					}
					$i++
				}
				'^(-W|--Warning)$' {
					If ($value -match '^(?<size>[\d]+)(?<unit>(?:[kMGT]i?|[kMGT]?))(?<reverse>\:?)$') {
						$Struct.WarningReverse = ($matches['reverse'] -eq ':')
						$Struct.WarningThreshold = [int]$matches['size']
						Switch ($matches['unit']) {
							"T"  {$Struct.WarningThreshold = $Struct.WarningThreshold * 1000 * 1000 * 1000 * 1000}
							"G"  {$Struct.WarningThreshold = $Struct.WarningThreshold * 1000 * 1000 * 1000}
							"M"  {$Struct.WarningThreshold = $Struct.WarningThreshold * 1000 * 1000}
							"k"  {$Struct.WarningThreshold = $Struct.WarningThreshold * 1000}
							"Ti" {$Struct.WarningThreshold = $Struct.WarningThreshold * 1024 * 1024 * 1024 * 1024}
							"Gi" {$Struct.WarningThreshold = $Struct.WarningThreshold * 1024 * 1024 * 1024}
							"Mi" {$Struct.WarningThreshold = $Struct.WarningThreshold * 1024 * 1024}
							"ki" {$Struct.WarningThreshold = $Struct.WarningThreshold * 1024}
						}
					}
					Else {
						Throw ('Warning threshold should be numeric with optional unit (among k, ki, M, Mi, G, Gi, T, Ti) and optional : (colon) to reverse comparison operator, e.g. 10M:, 100ki... Value given is {0}.' -f $value)
					}
					$i++
				}
				'^(-C|--Critical)$' {
					If ($value -match '^(?<size>[\d]+)(?<unit>(?:[kMGT]i?|[kMGT]?))(?<reverse>\:?)$') {
						$Struct.CriticalReverse = ($matches['reverse'] -eq ':')
						$Struct.CriticalThreshold = [int]$matches['size']
						Switch ($matches['unit']) {
							"T"  {$Struct.CriticalThreshold = $Struct.CriticalThreshold * 1000 * 1000 * 1000 * 1000}
							"G"  {$Struct.CriticalThreshold = $Struct.CriticalThreshold * 1000 * 1000 * 1000}
							"M"  {$Struct.CriticalThreshold = $Struct.CriticalThreshold * 1000 * 1000}
							"k"  {$Struct.CriticalThreshold = $Struct.CriticalThreshold * 1000}
							"Ti" {$Struct.CriticalThreshold = $Struct.CriticalThreshold * 1024 * 1024 * 1024 * 1024}
							"Gi" {$Struct.CriticalThreshold = $Struct.CriticalThreshold * 1024 * 1024 * 1024}
							"Mi" {$Struct.CriticalThreshold = $Struct.CriticalThreshold * 1024 * 1024}
							"ki" {$Struct.CriticalThreshold = $Struct.CriticalThreshold * 1024}
						}
					} 
					Else {
						Throw ('Critical threshold should be numeric with optional unit (among k, ki, M, Mi, G, Gi, T, Ti) and optional : (colon) to reverse comparison operator, e.g. 10M:, 100ki... Value given is {0}.' -f $value)
					}
					$i++
				}
				'^(-AE|--AlertOnExist)$' {
					$Struct.AlertOnExist = $True
				}
				'^(-ANE|--AlertOnNotExist)$' {
					$Struct.AlertOnNotExist = $True
				}
				'^(-H|--Help)$' {
					Write-Help
				}
				default {
					Throw ('Illegal arguments detected: {0}' -f $_)
				}
			} # Switch
		} # For
		
		# File name is mandatory
		if ($Struct.File -eq '') {
			$CurrentArg = '-F'
			$Value = ''
			Throw ('File name is mandatory')
		}
	} 
	Catch {
		Write-Host ('CRITICAL: Argument: {0} Value: {1} Error: {2}' -f $CurrentArg, $Value, $_)
		Exit 2
	}
}

Function Test-Strings {
	Param ( [Parameter(Mandatory=$True,HelpMessage='String to check')][string]$String )
	$BadChars = @("``", '|', ';', "`n")
	$BadChars | ForEach-Object {
		If ( $String.Contains(('{0}' -f $_)) ) {
			Write-Host ("Error: String `"{0}`" contains illegal characters." -f $String)
			Exit $Struct.ExitCode
		}
	}
	Return $true
}

Function Write-Help {
	Write-Host @'
check_ms_win_files.ps1: This script is designed to check Windows file presence and size.

Syntax:
	check_ms_win_files.ps1 -f FILENAME [ -ae ] [ -ane ] [ -w threshold ] [ -c threshold ]
	
Arguments:
  -f   | --File            => Full path of file or folder to check (mandatory).
  -ae  | --AlertOnExist    => Throw CRITICAL alert if file/folder exists.
  -ane | --AlertOnNotExist => Throw CRITICAL alert if file/folder doesn't exist.
  -w   | --Warning         => Size threshold for warning alert (0 if omitted).
  -c   | --Critical        => Size threshold for critical alert (0 if omitted).
  -h   | --Help            => Print this help output.

Threshold arguments:

  threshold ::= size [ unit ] [ reverse ] (all glued together, no space)
  size      ::= <positive number>
  unit      ::= <size multiplier among k, M, G, T, ki, Mi, Gi, Ti>
  reverse   ::= : (colon means alert is raised if the file size is <= threshold)
                  (empty means alert is raised if the file size is >= threshold)

  NB: Folder size is always equal to 1 byte, and does not represent the sum of
      contained files' size.

Examples:
  -w 4M -c 5M   (warning if >= 4000000 bytes, critical if >= 5000000 bytes)
  -w 4ki: -c 0: (warning if <= 4096 bytes, critical if zero)
  
'@
	Exit $Struct.ExitCode
} 

Function Check-File {
	Param (
		[Parameter(Mandatory=$True,ValueFromPipeline=$True,HelpMessage='File to check')][string]$File
	)
	Process {
		# First things first, check the presence or absence of the file if critical error must be thrown
		$fileExist = Test-Path $File
		
		If ($fileExist -eq $true) {	
			If ($Struct.AlertOnExist -eq $true) {	
				$OutputString =  "CRITICAL: File '$($Struct.File)' exists"
				$Struct.ExitCode = 2
			} Else {
				$fileSize = (Get-Item $File).length

				If (($Struct.WarningReverse -eq $false) -and ($fileSize -ge $Struct.WarningThreshold)) {
					$OutputString =  "WARNING | File '$($Struct.File)' exceeds WARNING threshold size ($fileSize b >= $($Struct.WarningThreshold) b)"
					$Struct.ExitCode = 1
				} ElseIf (($Struct.WarningReverse -eq $True) -and ($fileSize -le $Struct.WarningThreshold)) {
					$OutputString =  "WARNING | File '$($Struct.File)' doesn't meet WARNING threshold minimal size ($fileSize b <= $($Struct.WarningThreshold) b)"
					$Struct.ExitCode = 1
				} Else {
					$OutputString =  "OK: File '$($Struct.File)' present ($fileSize b)"
					$Struct.ExitCode = 0
				}

				If (($Struct.CriticalReverse -eq $false) -and ($fileSize -ge $Struct.CriticalThreshold)) {
					$OutputString =  "CRITICAL: File '$($Struct.File)' exceeds CRITICAL threshold size ($fileSize b >= $($Struct.CriticalThreshold) b)"
					$Struct.ExitCode = 2
				} ElseIf (($Struct.CriticalReverse -eq $True) -and ($fileSize -le $Struct.CriticalThreshold)) {
					$OutputString =  "CRITICAL: File '$($Struct.File)' doesn't meet CRITICAL threshold minimal size ($fileSize b <= $($Struct.CriticalThreshold) b)"
					$Struct.ExitCode = 2
				}
			}
		} Else {
			If ($Struct.AlertOnNotExist -eq $true) {	
				# File does not exist and it's a problem
				$OutputString =  "CRITICAL: File '$($Struct.File) ' doesn't exist"
				$Struct.ExitCode = 2
			} Else {
				If (($Struct.CriticalReverse -eq $True) -and (0 -le $Struct.CriticalThreshold)) {
					$OutputString =  "CRITICAL: Absent file '$($Struct.File)' doesn't meet CRITICAL threshold minimal size (0 b <= $($Struct.CriticalThreshold) b)"
					$Struct.ExitCode = 2
				} ElseIf (($Struct.WarningReverse -eq $True) -and (0 -le $Struct.WarningThreshold)) {
					$OutputString =  "WARNING: Absent file '$($Struct.File)' doesn't meet WARNING threshold minimal size (0 b <= $($Struct.WarningThreshold) b)"
					$Struct.ExitCode = 1
				} Else {
					$OutputString =  "OK: File '$($Struct.File)' absent"
					$Struct.ExitCode = 0
				}
			}
		}
		
		Write-Host ('{0}' -f $outputString.replace('/','//').replace('\','\\'))
		Exit $Struct.ExitCode
	}
}
#endregion Functions

#region Main
If ( $Args ) {
	If ( ! ( $Args[0].ToString()).StartsWith('$') ) {
		If ( $Args.count -ge 1 ) {
			Initialize-Args -Args $Args
		}
	} Else {
		Write-Host ('CRITICAL: Seems like something is wrong with your parameters: Args: {0}.' -f $Args)
		Exit 2
	}
	Check-File($Struct.File)
	Write-Host 'UNKNOWN: Script exited in an abnormal way. Please debug...'
	Exit $Struct.ExitCode
} Else {
	Write-Help
}
#endregion Main