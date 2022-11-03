<#
.SYNOPSIS
Allows you to check for and apply IntelliFlash Best Practice settings on Windows Server 2012 R2, 2016, & 2019

.DESCRIPTION
This script will apply IntelliFlash Best Practice Settings on a Windows Server 2012 R2, 2016, or 2019 Host.

It must be run with Administrator privileges, and ALWAYS requires a reboot if settings are changed.

Always re-run it after reboot to verify, if it has to install MPIO on first run then more settings apply after reboot.

If iSCSI Initiator service is not running, it will prompt you with option to automatically enable it. Skip this if only using FC.

If MPIO is not installed, it will handle that for you, but some registry entries aren't available without it so you'll need to run again after reboot.

The script has several optional parameters, which will autocomplete after '-':

	-iSCSI | Automatically enable iSCSI initiator without being prompted
	-TDPS | Check TDPS version
	-AutoApply | Automatically apply all recommended settings without being prompted
	-SkipUpdate | This script will automatically try to find, download, and use the latest version of this script available. The -SkipUpdate switch will disable the automatic update check.
	-FConly | The -FConly option will only check for and optionally apply FC related settings.
	-BackupMediaServer | This switch is used to apply a PDORemovePeriod of 20. This can be benefitial to backup media servers, or any other applications which regularly mount/remount LUNs and/or Clones.
	-Version (alias: -ver, -v) | Returns script version

.EXAMPLE
.\IntelliFlash-Windows-Host-Validation.ps1 -Version
Displays the current script version

.EXAMPLE
.\IntelliFlash-Windows-Host-Validation.ps1 -iscsi -autoapply
Automatically starts the iSCSI initiator service & applies all recommended settings without prompting

.LINK
https://intelliflash.io
#>


[CmdletBinding(ConfirmImpact='Medium')]

	Param(
		[Parameter()]
		[switch]
		$iSCSI,
		[Parameter()]
		[switch]
		$TDPS,
		[Parameter()]
		[Switch]
		$AutoApply,
		[Parameter()]
		[Alias("v")] 
		[Alias("ver")] 
		[Switch]
		$Version,
		[Switch]
		$SkipUpdate,
		[Switch]
		$BackupMediaServer,
		[Switch]
		$FConly
	)

    Begin{
		# Variables for IntelliFlash Host Configuration:
		# MPIO Settings:
		$Recommended_PathVerificationState = "Enabled"
		$Recommended_PathVerificationStateReg = "1"  #actual value entry for registry; 0=Disabled, 1=Enabled
		$Recommended_PathVerificationPeriod = "5"
		$Recommended_RetryCount = "100"
		$Recommended_RetryInterval = "1"
		$Recommended_DiskTimeoutValue = "180" #This value is adjusted based on the BackupMediaServer Variable.
		# iSCSI-Specific Settings:
		$Recommended_MaxRequestHoldTime = "60"
		$Recommended_LinkDownTime = "15"
		$Recommended_iSCSIioSize = "131072"  #this sets the MaxTransferLength and FirstBurstLength registry values
		# 2016+2019-Specific Settings:
		$Recommended_UseCustomPathRecoveryTime = "Enabled"
		$Recommended_UseCustomPathRecoveryTimeReg = "1"  #actual value entry for registry; 0=Disabled, 1=Enabled
		$Recommended_CustomPathRecoveryTime = "40"
		# End of IntelliFlash Host Configuration Variables

		$MajorVer = 3
		$MinorVer = 11
		$PatchVer = 0
		$BuildVer = 4
		$VerMonth = 08
		$VerDay = 26
		$VerYear = 2020
		$Author = "Ken Nothnagel & Ben Kendall, Tintri IntelliFlash PS"
		$VerMonthName = (Get-Culture).DateTimeFormat.GetAbbreviatedMonthName($VerMonth)
		$LogReport += $EachLog
		$scriptpath = Split-Path -parent $MyInvocation.MyCommand.Definition
		$InvokeTimestamp = Get-Date -UFormat "%Y%m%d%H%M%S"
		$scriptname = $MyInvocation.MyCommand | select -ExpandProperty Name
		if ($Version){
			$VerReport = @()
			$EachVer = New-Object -TypeName PSObject
			$EachVer | Add-Member -Type NoteProperty -Name Vendor -Value "Tintri IntelliFlash"
			$EachVer | Add-Member -Type NoteProperty -Name Author -Value $Author
			$EachVer | Add-Member -Type NoteProperty -Name Version -Value "$MajorVer.$MinorVer.$PatchVer.$BuildVer"
			$EachVer | Add-Member -Type NoteProperty -Name Date -Value "$VerMonthName $VerDay, $VerYear"
			$VerReport += $EachVer
			Write-Output $VerReport
			Exit 0
		}
		If($FConly -And $iSCSI){
			Clear
			Write-Host "`nYou cannot use both the -FConly and -iSCSI switches simultaneously.`n" -ForegroundColor Red -BackgroundColor Black
			break
		}
		#Check for administrator role.
		If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
			[Security.Principal.WindowsBuiltInRole] "Administrator"))
		{
			Write-Error "You do not have Administrator rights.`nPlease re-run this script as an Administrator!"
			Break
		}
       
		#Check for OS Version.
		$CurrentOSVersion = [version](Get-CimInstance Win32_OperatingSystem).Version
		$Win2012R2Ver = [version]'6.3.9600'
		$Win2016RTMVer = [version]'10.0.14393'
		$Win2019OSVersion = [version]'10.0.17763'
		$OS_Description = (Get-WmiObject Win32_OperatingSystem).Name
		If ($CurrentOSVersion -lt $Win2012R2Ver -or $OS_Description -notlike "*Server 201*"){
			Write-Host "This function is compatible with Windows Server 2012 R2, 2016, and 2019 Only" -BackgroundColor Black -ForegroundColor Yellow; Break
			#CAN DISPLAY ALL RECOMMENDATIONS FOR OTHER OS
		}
		If ($currentOSVersion -ge $Win2016RTMVer) {
			$2016SVR = "Yes"
			} else {
			$2016SVR = "No"
		}
		$DISCLAIMER = "DISCLAIMER`r`n`r`nThis script is provided AS IS without warranty of any kind. Tintri by DDN further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose. The entire risk arising out of the use or performance of this script and documentation remains with you. In no event shall Tintri by DDN, or anyone else involved in the creation, production, or delivery of this script be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use this script or documentation, even if Tintri by DDN has been advised of the possibility of such damages.`r`n`r`nThis Script should only be run with the direct supervision of a Tintri Engineer."
		$RUNDATETIME = Get-Date -UFormat "%Y%m%d%H%M%S"
		$LOGFILE = "$RUNDATETIME.$env:computername.IntelliFlash.log"
		$LOG = "$RUNDATETIME.$env:computername.MPIO.tmp"
		$LogReport = @()
		$AUTO = "NO"
		$EachLog = New-Object -TypeName PSObject
		$EachLog | Add-Member -Type NoteProperty -Name StartDate -Value $RUNDATETIME
		$EachLog | Add-Member -Type NoteProperty -Name LogFile -Value $LOGFILE

	}
	Process{
		if (!$SkipUpdate) {
			# Check Script Version against the one on s1.tegile.com, offer to update if they're different:
			$url = "http://s1.tegile.com/ps/windows/IntelliFlash-Windows-Host-Validation.ps1"
			$s1vertestscript = "$scriptpath\IntelliFlash-Windows-Host-Validation-PowerCLI-s1VerTest-$InvokeTimestamp.ps1"
			$Error.Clear()
			Invoke-WebRequest -Uri $url -OutFile "$s1vertestscript"
			If (!$Error){
				# Get version info from local and downloaded scripts to compare, and convert to strings:
				$s1version = (Invoke-Expression "& '$s1vertestscript' -version")
				$currentversion = Invoke-Expression "& '$scriptpath\$scriptname' -version"
				$s1version = [Version]$s1version.version
				$currentversion = [Version]$currentversion.version
				if ($currentversion) {
					Write-Debug -Message $currentversion
					} else {
					Write-Debug -Message "Unable to collect local script version"
				}
				if ($s1version) {
					Write-Debug -Message $s1version
					} else {
					Write-Debug -Message "Unable to collect online script version"
				}
				if ($s1version -gt $currentversion) {
					Write-Host "`nYour version of the script is older than '$url'!!!" -foregroundcolor red
					Write-Host "`nThe updated script version on s1.tegile.com is:" -foregroundcolor yellow
					write-host $s1version -foregroundcolor green
					Write-Host "`nYour local script version is:" -foregroundcolor yellow
					write-host $currentversion -foregroundcolor red
					$answer = Read-Host "`nEnter 'y' to update the script, anything else to continue: "
					if ($answer -eq "y") {
						Write-Host "`nReplacing script with updated version as requested, and restarting it with same parameters for you..." -foregroundcolor green
						del "$scriptpath\$scriptname"
						$scriptname = $scriptname.Replace("Tegile","IntelliFlash")
						ren "$s1vertestscript" "$scriptname"
						Write-Host "Restarting script in:"
						$i=5
						Do {
							Write-Host $i
							sleep 1
							$i = $i - 1
						} while ($i -ne 0)
						Write-Host "Restarting script..."
						powershell.exe $MyInvocation.Line
						Exit 0
					} else {
						Write-Host "`nContinuing with current version of script as requested..." -foregroundcolor yellow
						del "$s1vertestscript"
					}
				} else {
					Write-Debug -Message "The online script is not newer than the local script."
					sleep 1
					del "$s1vertestscript"
				}
			} else {
			Write-Host "`nUnable to check for the current script. Verify access to http://s1.tegile.com/ps and try again.`n" -foregroundcolor yellow
			Pause
			}
		} else {
			Write-Host "`nSkipping the script version and update check, as requested"
		}
		If(!$BackupMediaServer){
			Clear
			Write-Host "Does this server mount/remount LUNs/Clones on a regular basis? This is common for backup media servers but can be a function of other types of servers as well."
			$title = ""
			$message = "`r`nBackup Media Server??`r`n`r`n"
			$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", ""
			$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", ""
			$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
			$MediaServerQ = $host.ui.PromptForChoice($title, $message, $options, 1)
			If ($MediaServerQ -eq 0){
				$Recommended_PDORemovePeriod = "20"
			}Else{
				$Recommended_PDORemovePeriod = "180"
			}
		}Else{
			$Recommended_PDORemovePeriod = "20"
		}
		if ($FConly){$EachLog | Add-Member -Type NoteProperty -Name FConly -Value "True"}Else{$EachLog | Add-Member -Type NoteProperty -Name FConly -Value "False"}
		$error.clear()
		Clear
		write-host $DISCLAIMER
		if (!$AUTOAPPLY) {
			$title = ""
			$message = "`r`nAccept Disclaimer?`r`n`r`n"
			$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Accept and continue"
			$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Quit now"
			$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
			$ACCEPTED = $host.ui.PromptForChoice($title, $message, $options, 1) 
			if ($ACCEPTED -eq 1){$EachLog | Add-Member -Type NoteProperty -Name Disclaimer -Value "Not-Accepted";$LogReport += $EachLog;Write-Output $LogReport;Break} Else {$EachLog | Add-Member -Type NoteProperty -Name Disclaimer -Value "Accepted"}
			$EachLog | Add-Member -Type NoteProperty -Name AutoApply -Value $AUTO
		} Else {
			write-host "Disclaimer is automatically accepted when using -autoapply"
			$EachLog | Add-Member -Type NoteProperty -Name Disclaimer -Value "Auto-Accepted"
			$EachLog | Add-Member -Type NoteProperty -Name AutoApply -Value $AUTO
        }
		
		If(!$FConly){
			$iscsiiosize = $Recommended_iSCSIioSize
			$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Recommended-MaxTransferLength -Value $iscsiiosize
			$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Recommended-FirstBurstLength -Value $iscsiiosize

			# Check status of MSiSCSI Service and provide or capture option to enable and start it:
			$ISCSISTARTUP = "UNKNOWN"
			$iscsiservice = "UNKNOWN"
			$iscsiservice = (Get-Service -Name MSiSCSI)
			if ($iscsiservice.status -ne "Running" ){
				if ($iscsi){
					$ISCSISTARTUP = "YES"
					$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Service_Startup_AutoApply -Value "Applied"
				} ElseIf ($AUTOAPPLY){
					$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Service_Startup_AutoApply -Value "Skipped"				
				} Else {
				$title = ""
				$message = "`r`niSCSI Service isn't running, start it?`r`n`r`n"
				$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Start MSiSCSI Service and set to Automatic Startup"
				$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Leave MSiSCSI Service Off"
				$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
				$STARTISCSI = $host.ui.PromptForChoice($title, $message, $options, 1) 
				if ($STARTISCSI -eq 0){$ISCSISTARTUP = "YES"}
				}
			}

			# Now we'll attempt to start the MSiSCSI Service if determined from above that we should
			if ($ISCSISTARTUP -eq "YES"){
				$error.clear()
				Set-Service -Name MSiSCSI -StartupType Automatic
				if ($error){$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Service_SetStartupType -Value "Failed"} Else {$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Service_SetStartupType -Value "Automatic"}
				Start-Service -Name MSiSCSI
				if ($error){$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Service_StartService -Value "Failed"} Else {$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Service_StartService -Value "Started"}
				$iscsiservice = (Get-Service -Name MSiSCSI)
				if ($iscsiservice.status -ne "Running"){write-host "`r`nMSiSCSI Service Failed to Start" -foregroundcolor red} Else {write-host "`r`nMSiSCSI Service Started"}
			}

			# One last check again to see if MSiSCSI is running or not after previous options to enable it, then proceeding:
			$iscsiservice = (Get-Service -Name MSiSCSI)
			if ($iscsiservice.status -ne "Running" ){
			write-host "`r`n`r`nTo check and apply iSCSI settings, MSiSCSI Service needs to be running" -BackgroundColor Black -ForegroundColor Yellow
			$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Service_Status -Value "Stopped"
		} Else {
			$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Service_Status -Value "Running"
			$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Recommended-MaxRequestHoldTime -Value $Recommended_MaxRequestHoldTime
			$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Recommended-LinkDownTime -Value $Recommended_LinkDownTime

			#FIND THE RIGHT REGISTRY KEY FOR ISCSI INITIATOR
			$iscsipath = Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Control\Class\"{4d36e97b-e325-11ce-bfc1-08002be10318}" -Recurse -ErrorAction SilentlyContinue |Get-ItemProperty -name DriverDesc -ErrorAction SilentlyContinue|Where {$_.DriverDesc -like "Microsoft iSCSI Initiator"}|foreach {echo $_.PSPath}
			$iscsipath = "$iscsipath\Parameters"
			$iscsipath_log = "`"$iscsipath`""
			$MTL = (get-item -path $iscsipath |Get-ItemProperty -ErrorAction SilentlyContinue -name MaxTransferLength)
			$FBL = (get-item -path $iscsipath |Get-ItemProperty -ErrorAction SilentlyContinue -name FirstBurstLength)
			$MRHT = (get-item -path $iscsipath |Get-ItemProperty -ErrorAction SilentlyContinue -name MaxRequestHoldTime)
			$LDT = (get-item -path $iscsipath |Get-ItemProperty -ErrorAction SilentlyContinue -name LinkDownTime)

			$MTL = $MTL.MaxTransferLength
			$FBL = $FBL.FirstBurstLength
			$MRHT = $MRHT.MaxRequestHoldTime
			$LDT = $LDT.LinkDownTime
			$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Original-MaxTransferLength -Value $MTL
			$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Original-FirstBurstLength -Value $FBL
			$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Original-MaxRequestHoldtime -Value $MRHT
			$EachLog | Add-Member -Type NoteProperty -Name ISCSI-Original-MaxLinkDownTime -Value $LDT

			#Check for single initiator side IPs per NIC

			$iSCSISession = Get-IscsiSession
			$SameSubnet = "NO"
			ForEach ($Session in $iSCSISession){
				[ipaddress]$CurrentIP = $Session.InitiatorPortalAddress
				$CurrentTarget = $Session.TargetNodeAddress
				ForEach ($Check in $iSCSISession){
					$C1 = $Check.TargetNodeAddress
					[ipaddress]$C2 = $Check.InitiatorPortalAddress
					If ($CurrentTarget -eq $C1){
						If ($CurrentIP){
							$A1 = $CurrentIP.GetAddressBytes()
							$B1 = $C2.GetAddressBytes()
							If (($A1[0] -eq $B1[0]) -and ($A1[1] -eq $B1[1]) -and ($A1[2] -eq $B1[2]) -and ($A1[3] -ne $B1[3])){
								Write-Verbose "These two Initiator IPs seem to be on the same subnet:"
								Write-Verbose $CurrentIP.IPAddressToString
								Write-Verbose $C2.IPAddressToString
								$SameSubnet = "YES"
							}
						} 
					}
				}
			}

			$EachLog | Add-Member -Type NoteProperty -Name ISCSI-MultipleIPsSameSubnet -Value $SameSubnet
			If ($SameSubnet -eq "YES"){Write-Host "This host appears to have multiple iSCSI initiator IPs on the same subnet.`r`nIntelliFlash Support recommends adjusting so you have a single initiator side IP on each subnet.`r`nPlease work with IntelliFlash Support or IntelliFlash Professional Services for assistence if needed.`r`n" -ForegroundColor Yellow -BackgroundColor Black}

			#Check for Network Services enabled on iSCSI interfaces
			$NetBindReport = @()
			$iscsiip = Get-IscsiSession|select InitiatorPortalAddress
			$iscsiip = $iscsiip.InitiatorPortalAddress
			$iscsiip = $iscsiip|Sort -Unique
			ForEach ($IP in $iscsiip){
				If ($IP -eq "0.0.0.0"){
					Write-Host "`r`n`r`nYou have 0.0.0.0 configured as an iSCSI initiator IP on this server, which is not a valid iSCSI Configuration for IntelliFlash iSCSI connections. Please contact IntelliFlash Customer Support or IntelliFlash Professional Services for assistence adjusting these connections if needed.`r`n" -BackgroundColor Black -ForegroundColor Red
					$EachLog | Add-Member -Type NoteProperty -Name ISCSI-INITIATOR-MISCONFIG -Value "YES"
					pause
				}
				$IntName = Get-NetIPAddress |Where {$_.IPAddress -eq $IP}|Select InterfaceAlias
				If ($IntName){
					$IscsiBinding = Get-NetAdapterBinding -Name $IntName.InterfaceAlias
					$NetBindEnabled = $IscsiBinding|Where {$_.Enabled -eq "True" -and $_.DisplayName -ne "Internet Protocol Version 4 (TCP/IPv4)"}
					$NetBindReport += $NetBindEnabled
				}
			}
			If ($NetBindReport){
				Write-Host "`r`n`r`nIf the currently connected iSCSI network interfaces ONLY serve iSCSI then the following network services should be disabled on these interfaces:`r`n" -BackgroundColor Black -ForegroundColor Yellow
				$NetBindReport
				$EachLog | Add-Member -Type NoteProperty -Name ISCSI-NetBindingsToRemove -Value "YES"
			} Else {
				$EachLog | Add-Member -Type NoteProperty -Name ISCSI-NetBindingsToRemove -Value "NO"
			}

			

		
			#DISPLAY RECOMMENDATIONS FOR THE ISCSI INITIATOR

			if ($MTL -ne $iscsiiosize) {write-host "`r`nMaxTransferLength is set to $MTL `t`t<== Should be $iscsiiosize" -foregroundcolor red;$CHANGES += "get-item -path ""$iscsipath"" |Set-ItemProperty -ErrorAction SilentlyContinue -name MaxTransferLength -value $iscsiiosize`n"} Else {write-host "`r`nMaxTransferLength is set to $MTL which is good."}
			if ($FBL -ne $iscsiiosize) {write-host "FirstBurstLength is set to $FBL `t`t<== Should be $iscsiiosize" -foregroundcolor red;$CHANGES += "get-item -path ""$iscsipath"" |Set-ItemProperty -ErrorAction SilentlyContinue -name FirstBurstLength -value $iscsiiosize`n"} Else {write-host "FirstBurstLength is set to $FBL which is good."}
			if ($MRHT -ne $Recommended_MaxRequestHoldTime) {write-host "MaxRequestHoldTime is set to $MRHT `t`t<== Should be $Recommended_MaxRequestHoldTime" -foregroundcolor red;$CHANGES += "get-item -path ""$iscsipath"" |Set-ItemProperty -ErrorAction SilentlyContinue -name MaxRequestHoldTime -value $Recommended_MaxRequestHoldTime`n"} Else {write-host "MaxRequestHoldTime is set to $MRHT which is good."}
			if ($LDT -ne $Recommended_LinkDownTime) {write-host "LinkDownTime is set to $LDT `t`t`t<== Should be $Recommended_LinkDownTime`r`n" -foregroundcolor red;$CHANGES += "get-item -path ""$iscsipath"" |Set-ItemProperty -ErrorAction SilentlyContinue -name LinkDownTime -value $Recommended_LinkDownTime`n"} Else {write-host "LinkDownTime is set to $LDT which is good.`r`n"}
		}
		}
		#Check for Hotfixes
			Write-Progress -Activity "Checking installed hotfixes"
			$OS_Root = (Get-ChildItem Env:|Where {$_.Name -eq "SystemRoot"})
			$MPIOVer = (Get-WmiObject Win32_PnPSignedDriver| select devicename, driverversion|Where {$_.devicename -eq "Microsoft Multi-Path Bus Driver"})
			$MPIOVer = [version]$MPIOVer.driverversion
			$MSDSMVer = (Get-WmiObject Win32_PnPSignedDriver| select devicename, driverversion|Where {$_.devicename -eq "Microsoft Multi-Path Device Specific Module"})
			$MSDSMVer = [version]$MSDSMVer.driverversion
			$STORPORTPath = $OS_Root.Value + "\System32\drivers\storport.sys"
			$STORPORTVer = [version](Get-Item $STORPORTPath).VersionInfo.ProductVersion
			Write-Progress -Completed -Activity "Checking installed hotfixes"
			If ($MPIOVer -and ($MPIOVer -lt [version]"6.3.9600.18007")){
				Write-Host "KB3078420 is missing. Please download and install : https://support.microsoft.com/en-us/kb/3078420" -BackgroundColor Black -ForegroundColor Yellow
				$EachLog | Add-Member -Type NoteProperty -Name ISCSI-KB3078420-Missing -Value "True"
			} Else {$EachLog | Add-Member -Type NoteProperty -Name ISCSI-KB3078420-Missing -Value "False"}
			If ($MSDSMVer -and ($MSDSMVer -lt [version]"6.3.9600.17809")){
				Write-Host "KB3046101 is missing. Please download and install : https://support.microsoft.com/en-us/kb/3046101" -BackgroundColor Black -ForegroundColor Yellow
				$EachLog | Add-Member -Type NoteProperty -Name ISCSI-KB3046101-Missing -Value "True"
			} Else {$EachLog | Add-Member -Type NoteProperty -Name ISCSI-KB3046101-Missing -Value "False"}
			If ($STORPORTVer -and ($STORPORTVer -lt [version]"6.3.9600.17937")){
				Write-Host "KB3080728 is missing. Please download and install : https://support.microsoft.com/en-us/kb/3080728" -BackgroundColor Black -ForegroundColor Yellow
				$EachLog | Add-Member -Type NoteProperty -Name ISCSI-KB3080728-Missing -Value "True"
			} Else {$EachLog | Add-Member -Type NoteProperty -Name ISCSI-KB3080728-Missing -Value "False"}
			If ($CurrentOSVersion -eq $Win2012R2Ver -And !$FConly){
				$FixCheck = (get-wmiobject -class win32_quickfixengineering |Where {$_.HotFixID -eq "KB2955164"})
				If (!$FixCheck){
					Write-Host "KB2955164 is missing. Please download and install : `nhttps://support.microsoft.com/en-us/help/2908783/data-corruption-occurs-on-iscsi-luns-in-windows`n`nThe above link has been added to your clipboard." -BackgroundColor Black -ForegroundColor Red
					Echo "https://support.microsoft.com/en-us/help/2908783/data-corruption-occurs-on-iscsi-luns-in-windows" | Clip
					$EachLog | Add-Member -Type NoteProperty -Name ISCSI-KB2955164-Missing -Value "True"
					Break
					}Else{
					$EachLog | Add-Member -Type NoteProperty -Name ISCSI-KB2955164-Missing -Value "False"
				}
			}
			If ($CurrentOSVersion -eq $Win2016RTMVer -And !$FConly){
					Write-Host "Please update the OS with all the recommended updates from Microsoft." -BackgroundColor Black -ForegroundColor Red
			}
			If ($CurrentOSVersion -eq $Win2019OSVersion -And !$FConly){
					Write-Host "Please update the OS with all the recommended updates from Microsoft." -BackgroundColor Black -ForegroundColor Red
			}
		#Check for TDPS
		If ($TDPS){
			$TDPSReg = $()
			$TDPSSearchProgress = 0
			Write-Progress -Activity "Checking the registry for TDPS" -Status "Progress:" -PercentComplete $TDPSSearchProgress
			$TDPSReg = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData" -Recurse |ForEach-Object {
				Get-ItemProperty $_.pspath 
				$TDPSSearchProgress++
				If ($TDPSSearchProgress -eq 99){$TDPSSearchProgress = 1}
				Write-Progress -Activity "Checking the registry for TDPS" -Status "Progress:$_" -percentcomplete ($TDPSSearchProgress)
				} |Where-Object {$_.DisplayName -eq "Tegile Data Protection Services"}
			Write-Progress -Activity "Checking the registry for TDPS" -Completed
			If ($TDPSReg){
				$TDPSCurrentVer = [version]'2.1.0.18'
				$TDPSInstalledVer = [version]$TDPSReg.DisplayVersion

				If ($TDPSInstalledVer -lt $TDPSCurrentVer){
					Write-Host "Your TDPS Version is out of date" -ForegroundColor Yellow -BackgroundColor Black
					Write-Host "TDPS Installed: $TDPSInstalledVer" -ForegroundColor Yellow -BackgroundColor Black
					Write-Host "Current TDPS Version: $TDPSCurrentVer" -ForegroundColor Yellow -BackgroundColor Black
					$EachLog | Add-Member -Type NoteProperty -Name TDPS-Installed -Value "True"
					$EachLog | Add-Member -Type NoteProperty -Name TDPS-Outdated -Value "True"
					$EachLog | Add-Member -Type NoteProperty -Name TDPS-Installed-Version -Value $TDPSInstalledVer
				} Else {
					Write-Verbose "TDPS is up to date"
					Write-Verbose "TDPS installed version: $TDPSInstalledVer"
					$EachLog | Add-Member -Type NoteProperty -Name TDPS-Installed -Value "True"
					$EachLog | Add-Member -Type NoteProperty -Name TDPS-Outdated -Value "False"
					$EachLog | Add-Member -Type NoteProperty -Name TDPS-Installed-Version -Value $TDPSInstalledVer
				}
			} Else {
				$EachLog | Add-Member -Type NoteProperty -Name TDPS-Installed -Value "False"
				Write-host "TDPS Not Installed"
			}
		} Else {
			$EachLog | Add-Member -Type NoteProperty -Name TDPS-Checked -Value "False"
		}
		#Check for PowerShell-V2 Backward Compatibility
		$PS2Engine = Get-WindowsFeature|Where {$_.Name -eq "PowerShell-V2"}
		If($PS2Engine.Installed -eq "True"){
			Write-Verbose "PowerShell-V2 installed"
			$EachLog | Add-Member -Type NoteProperty -Name TDPS-PowerShell-V2-Installed -Value "True"
		} Else {
			Write-host "PowerShell-V2 NOT Installed" -ForegroundColor Yellow -BackgroundColor Black
			Write-host "PowerShell-V2 is required for TDPS"-ForegroundColor Yellow -BackgroundColor Black
			$EachLog | Add-Member -Type NoteProperty -Name TDPS-PowerShell-V2-Installed -Value "False"
		}
		#CHECK IF MPIO IS ENABLED
		$pidintelliflash = "Missing"
		Write-Progress -Activity "Checking for MPIO" -Status "Checking..."
		$mpioenabled = Get-WindowsOptionalFeature -Online -FeatureName MultiPathIO|Select-Object state
		Write-Progress -Activity "Checking for MPIO" -Status "Checking..." -Completed
		if (!$mpioenabled){$mpioenabled = "Disabled or Missing"} Else {$mpioenabled = $mpioenabled.state}
		If ($mpioenabled -eq "Enabled"){
			$vidpid = Get-MSDSMSupportedHW|where {$_.VendorId -eq "TEGILE"} |ForEach-Object {
				if ($_.ProductId -eq "INTELLIFLASH") {$pidintelliflash = "Good"}
			}
			$EachLog | Add-Member -Type NoteProperty -Name SAN-Original-PID-INTELLIFLASH -Value $pidintelliflash

			#CHECK MPIO SETTINGS
			Write-Progress -Activity "Checking MPIO Settings" -Status "Checking..."
			Get-MPIOSetting > .\$LOG
			Write-Progress -Activity "Checking MPIO Settings" -Status "Checking..." -Completed
			$PathVerificationStateTmp = ((get-itemproperty "HKLM:\System\CurrentControlSet\Services\msdsm\Parameters").PathVerifyEnabled)
			$PathVerificationState = "PathVerificationState     : Disabled"
			If ($PathVerificationStateTmp -eq "1"){$PathVerificationState = "PathVerificationState     : Enabled"}
			$PathVerificationPeriod = (Get-Content .\$LOG)[3]
			$RetryCount = (Get-Content .\$LOG)[5]
			$PDORemovePeriod = (Get-Content .\$LOG)[4]
			$RetryInterval = (Get-Content .\$LOG)[6]
			$DiskTimeoutValue = (Get-Content .\$LOG)[9]
			If ($2016SVR -eq "Yes") {
				$UseCustomPathRecoveryTime = (Get-Content .\$LOG)[7]
				$CustomPathRecoveryTime = (Get-Content .\$LOG)[8]
			}
			Remove-Item .\$LOG
			$EachLog | Add-Member -Type NoteProperty -Name SAN-Original-PathVerificationState -Value ($PathVerificationState.Substring(28))
			$EachLog | Add-Member -Type NoteProperty -Name SAN-Original-PathVerificationPeriod -Value ($PathVerificationPeriod.Substring(28))
			$EachLog | Add-Member -Type NoteProperty -Name SAN-Original-RetryCount -Value ($RetryCount.Substring(28))
			$EachLog | Add-Member -Type NoteProperty -Name SAN-Original-PDORemovePeriod -Value ($PDORemovePeriod.Substring(28))
			$EachLog | Add-Member -Type NoteProperty -Name SAN-Original-RetryInterval -Value ($RetryInterval.Substring(28))
			$EachLog | Add-Member -Type NoteProperty -Name SAN-Original-DiskTimeoutValue -Value ($DiskTimeoutValue.Substring(28))
			If ($2016SVR -eq "Yes") {
				$EachLog | Add-Member -Type NoteProperty -Name SAN-Original-UseCustomPathRecoveryTime -Value ($UseCustomPathRecoveryTime.Substring(28))
				$EachLog | Add-Member -Type NoteProperty -Name SAN-Original-CustomPathRecoveryTime -Value ($CustomPathRecoveryTime.Substring(28))
			}
			Write-Host "`n"
			#CHECK AND MAKE MPIO SETTING RECOMMENDATIONS
			if ($PathVerificationState -ne "PathVerificationState     : $Recommended_PathVerificationState") {write-host "$PathVerificationState `t`t<== Should be Enabled" -foregroundcolor red;$CHANGES += "Remove-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\msdsm\Parameters -name PathVerifyEnabled -ErrorAction Ignore;New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\msdsm\Parameters -name PathVerifyEnabled -value $Recommended_PathVerificationStateReg -PropertyType DWord`n"} Else {write-host $PathVerificationState}
			if ($PathVerificationPeriod -ne "PathVerificationPeriod    : $Recommended_PathVerificationPeriod") {write-host "$PathVerificationPeriod `t`t`t<== Should be $Recommended_PathVerificationPeriod" -foregroundcolor red;$CHANGES += "Remove-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\msdsm\Parameters -name PathVerificationPeriod -ErrorAction Ignore;New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\msdsm\Parameters -name PathVerificationPeriod -value $Recommended_PathVerificationPeriod -PropertyType DWord`n"} Else {write-host $PathVerificationPeriod}
			if ($RetryCount -ne "RetryCount                : $Recommended_RetryCount") {write-host "$RetryCount `t`t`t<== Should be $Recommended_RetryCount" -foregroundcolor red;$CHANGES += "Remove-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\msdsm\Parameters -Name RetryCount -ErrorAction Ignore;New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\msdsm\Parameters -Name RetryCount -Value $Recommended_RetryCount -PropertyType DWord`n"} Else {write-host $RetryCount}
			if ($PDORemovePeriod -ne "PDORemovePeriod           : $Recommended_PDORemovePeriod") {write-host "$PDORemovePeriod `t`t<== Should be $Recommended_PDORemovePeriod" -foregroundcolor red;$CHANGES += "Remove-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\msdsm\Parameters -Name PDORemovePeriod -ErrorAction Ignore;New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\msdsm\Parameters -Name PDORemovePeriod -Value $Recommended_PDORemovePeriod -PropertyType DWord`n"} Else {write-host $PDORemovePeriod}
			if ($RetryInterval -ne "RetryInterval             : $Recommended_RetryInterval") {write-host "$RetryInterval `t`t`t<== Should be $Recommended_RetryInterval" -foregroundcolor red;$CHANGES += "Remove-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\msdsm\Parameters -Name RetryInterval -ErrorAction Ignore;New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\msdsm\Parameters -Name RetryInterval -Value $Recommended_RetryInterval -PropertyType DWord`n"} Else {write-host $RetryInterval}
			if ($DiskTimeoutValue -ne "DiskTimeoutValue          : $Recommended_DiskTimeoutValue") {write-host "$DiskTimeoutValue `t`t<== Should be $Recommended_DiskTimeoutValue" -foregroundcolor red;$CHANGES += "Remove-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\disk -Name TimeoutValue -ErrorAction Ignore;New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\disk -Name TimeoutValue -Value $Recommended_DiskTimeoutValue -PropertyType DWord`n"} Else {write-host $DiskTimeoutValue}
			If ($2016SVR -eq "Yes") {
				if ($UseCustomPathRecoveryTime -ne "UseCustomPathRecoveryTime : $Recommended_UseCustomPathRecoveryTime") {write-host "$UseCustomPathRecoveryTime `t`t<== Should be $Recommended_UseCustomPathRecoveryTime" -foregroundcolor red;$CHANGES += "Remove-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\mpio\Parameters -Name UseCustomPathRecoveryInterval -ErrorAction Ignore;New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\mpio\Parameters -Name UseCustomPathRecoveryInterval -Value $Recommended_UseCustomPathRecoveryTimeReg -PropertyType DWord`n"} Else {write-host $UseCustomPathRecoveryTime}
				if ($CustomPathRecoveryTime -ne "CustomPathRecoveryTime    : $Recommended_CustomPathRecoveryTime") {write-host "$CustomPathRecoveryTime `t`t<== Should be $Recommended_CustomPathRecoveryTime" -foregroundcolor red;$CHANGES += "Remove-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\mpio\Parameters -Name PathRecoveryInterval -ErrorAction Ignore;New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\mpio\Parameters -Name PathRecoveryInterval -Value $Recommended_CustomPathRecoveryTime -PropertyType DWord`n"} Else {write-host $CustomPathRecoveryTime}
			}
			$EachLog | Add-Member -Type NoteProperty -Name SAN-Recommended-PathVerificationState -Value $Recommended_PathVerificationState
			$EachLog | Add-Member -Type NoteProperty -Name SAN-Recommended-PathVerificationPeriod -Value $Recommended_PathVerificationPeriod
			$EachLog | Add-Member -Type NoteProperty -Name SAN-Recommended-RetryCount -Value $Recommended_RetryCount
			$EachLog | Add-Member -Type NoteProperty -Name SAN-Recommended-PDORemovePeriod -Value $Recommended_PDORemovePeriod
			$EachLog | Add-Member -Type NoteProperty -Name SAN-Recommended-RetryInterval -Value $Recommended_RetryInterval
			$EachLog | Add-Member -Type NoteProperty -Name SAN-Recommended-DiskTimeoutValue -Value $Recommended_DiskTimeoutValue
			If ($2016SVR -eq "Yes") {
				$EachLog | Add-Member -Type NoteProperty -Name SAN-Recommended-UseCustomPathRecoveryTime -Value $Recommended_UseCustomPathRecoveryTime
				$EachLog | Add-Member -Type NoteProperty -Name SAN-Recommended-CustomPathRecoveryTime -Value $Recommended_CustomPathRecoveryTime
			}
		}
		$EachLog | Add-Member -Type NoteProperty -Name SAN-MPIO -Value $mpioenabled

		#Show MPIO Requirement
		if ($mpioenabled -ne "Enabled") {write-host "`r`nMPIO Enabled = $mpioenabled `t`t`t`t<== MPIO must be enabled" -foregroundcolor red;$CHANGES += "Enable-WindowsOptionalFeature -Online -FeatureName MultiPathIO -NoRestart`n"} Else {write-host "`r`nMPIO Enabled = $mpioenabled"}
		
		#Suggest IntelliFlash VID/PID, and add commands to $CHANGES after first checking if MPIO cmdlet exists
		$mpiocmdlet = (get-command New-MSDSMSupportedHW -ErrorAction SilentlyContinue).Name
		if ($pidintelliflash -eq "Missing") {
			write-host "INTELLIFLASH = $pidintelliflash `t`t`t`t<== The INTELLIFLASH PID should be added" -foregroundcolor red
			if ($mpiocmdlet) {$CHANGES += "New-MSDSMSupportedHW -VendorId ""TEGILE"" -ProductId ""INTELLIFLASH""`n"}
		} Else {
			write-host "INTELLIFLASH = $pidintelliflash"
		}
		

		#################################
		#### SETTING CHECKS IS OVER #####
		#################################

		#ASK TO APPLY IntelliFlash BEST PRACTICES

		#SHOW THE RECOMMENDED CHANGES

		if (!$CHANGES){
			write-host "`nNo MPIO or iSCSI changes needed.`n"
		}Else{
			write-verbose "`r`nThe following changes are recommended:`r`n`r`n"
			write-verbose $CHANGES
			#ASK TO APPLY ALL SETTINGS
			if (!$AUTOAPPLY) {
				$title = ""
				$message = "`r`nUpdate All Settings with IntelliFlash Best Practices?`r`n`r`n"
				$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes","Yes: Applies all configuration settings above."
				$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "No: will prompt for each change."
				$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
				$APPLYALL = $host.ui.PromptForChoice($title, $message, $options, 1)
			} Else {
				$error.clear()
				If ($Changes){
					Invoke-Expression $CHANGES
					if ($error){
						write-host "`r`n`r`nErrors occurred during setting changes:`r`n$error" -foregroundcolor red
						$EachLog | Add-Member -Type NoteProperty -Name Status -Value "Complete"
						$EachLog | Add-Member -Type NoteProperty -Name Errors -Value "True"
					} Else {
						write-host "`r`n`r`nAll setting changes applied without errors."
						$EachLog | Add-Member -Type NoteProperty -Name Status -Value "Complete"
						$EachLog | Add-Member -Type NoteProperty -Name Errors -Value "False"
					}
					write-host "`r`n`r`nReboot is required to apply all changes. Re-run script after reboot!`r`n`r`n" -foregroundcolor yellow -backgroundcolor black
					$LogReport += $EachLog
					$LogReport > .\$LOGFILE
					$LogSort = Get-Content .\$Logfile -Raw
					$LogSort = $LogSort |Sort
					$LogSort > .\$LOGFILE
					If ($iscsipath_log){Echo "iSCSI Registry Path Used: $iscsipath_log" >> .\$logfile}
					Echo "`r`nThe following commands were applied:`r`n" >> .\$logfile
					$CHANGES > .\$LOG
					$ALLCHANGES = Get-Content .\$LOG
					Remove-Item .\$LOG
					$ALLCHANGES >> $LOGFILE
					break
				}Else{
					write-host "`r`n`r`nNo changes to apply.`r`n`r`n"
					$LogReport += $EachLog
					$LogReport > .\$LOGFILE
					$LogSort = Get-Content .\$Logfile -Raw
					$LogSort = $LogSort |Sort
					$LogSort > .\$LOGFILE
					If ($iscsipath_log){Echo "iSCSI Registry Path Used: $iscsipath_log" >> .\$logfile}
					Echo "`r`nNo changes to apply.`r`n`r`n" >> .\$logfile
					break
				}
			}

			if ($APPLYALL -eq 0){
				$error.clear()
				If($CHANGES){
					Invoke-Expression $CHANGES
					if ($error){write-host "`r`n`r`nErrors occurred during setting changes:`r`n$error" -foregroundcolor red} Else {write-host "`r`n`r`nAll setting changes applied without errors."}
					write-host "`r`n`r`nReboot is required to apply all changes. Re-run script after reboot!`r`n`r`n" -foregroundcolor yellow -backgroundcolor black
					$CHANGES > .\$LOG
					$ALLCHANGES = Get-Content .\$LOG
				}
			} Else {

				#ASK FOR EACH SETTING TO BE APPLIED
				#CREATE ARRAY OUT OF THE CHANGES
				$CHANGES > .\$LOG
				$ALLCHANGES = Get-Content .\$LOG
				Remove-Item .\$LOG
				Foreach ($CHANGE in $($ALLCHANGES | where {$_ -ne ""})){
					$title = "Apply this change?"
					$message = "`r`n$CHANGE`r`n`r`n"
					$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Yes will execute: $CHANGE"
					$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "No: will move on to the next change or exit."
					$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
					$APPLYCHANGE = $host.ui.PromptForChoice($title, $message, $options, 1)
					if ($APPLYCHANGE -eq 0){
						$error.clear()
						Invoke-Expression $CHANGE
						if ($error){write-host "`r`n`r`nErrors occurred executing: `r`n`r`n$CHANGE`r`n" -foregroundcolor red} Else {write-host "`r`nSetting change applied without errors."}
					}
				}
				write-host "`r`n`r`nReboot is required to apply all changes. Re-run script after reboot!`r`n" -foregroundcolor yellow -backgroundcolor black
			}
		}
	}
    End{
        $LogReport += $EachLog
        $LogReport > .\$LOGFILE
        $LogSort = Get-Content .\$Logfile
        $LogSort = $LogSort |Sort
        $LogSort > .\$LOGFILE
        If ($iscsipath_log){Echo "iSCSI Registry Path Used: $iscsipath_log" >> .\$logfile}
        Echo "`r`nThe following commands are recommended:`r`n" >> .\$logfile
        $ALLCHANGES >> $LOGFILE
        Start $LOGFILE
    }


