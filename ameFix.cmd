<# : batch portion
@echo off
whoami /user | findstr /i /c:S-1-5-18 >nul || ( call :RunAsTI "%~f0" %* & exit /b )

copy /y "%~f0" "%windir%\ameFix.cmd" > nul
if "%1"=="/afterRestart" (set afterRestart=true)

set "psScript=%~f0" & powershell -nop -c "if (Test-Path """env:afterRestart""") { $AfterRestart = $true }; Get-Content """$env:psScript""" -Raw | iex" & exit /b

#:RunAsTI snippet to run as TI/System, with innovative HKCU load, ownership privileges, high priority, and explorer support
set ^ #=& set "0=%~f0"& set 1=%*& powershell -c iex(([io.file]::ReadAllText($env:0)-split'#\:RunAsTI .*')[1])& exit /b
function RunAsTI ($cmd,$arg) { $id='RunAsTI'; $key="Registry::HKU\$(((whoami /user)-split' ')[-1])\Volatile Environment"; $code=@'
 $I=[int32]; $M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal"); $P=$I.module.gettype("System.Int`Ptr"); $S=[string]
 $D=@(); $T=@(); $DM=[AppDomain]::CurrentDomain."DefineDynami`cAssembly"(1,1)."DefineDynami`cModule"(1); $Z=[uintptr]::size
 0..5|% {$D += $DM."Defin`eType"("AveYo_$_",1179913,[ValueType])}; $D += [uintptr]; 4..6|% {$D += $D[$_]."MakeByR`efType"()}
 $F='kernel','advapi','advapi', ($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]), ([uintptr],$S,$I,$I,$D[9]),([uintptr],$S,$I,$I,[byte[]],$I)
 0..2|% {$9=$D[0]."DefinePInvok`eMethod"(('CreateProcess','RegOpenKeyEx','RegSetValueEx')[$_],$F[$_]+'32',8214,1,$S,$F[$_+3],1,4)}
 $DF=($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
 1..5|% {$k=$_; $n=1; $DF[$_-1]|% {$9=$D[$k]."Defin`eField"('f' + $n++, $_, 6)}}; 0..5|% {$T += $D[$_]."Creat`eType"()}
 0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -fo}; function F ($1,$2) {$T[0]."G`etMethod"($1).invoke(0,$2)}
 $TI=(whoami /groups)-like'*1-16-16384*'; $As=0; if(!$cmd) {$cmd='control';$arg='admintools'}; if ($cmd-eq'This PC'){$cmd='file:'}
 if (!$TI) {'TrustedInstaller','lsass','winlogon'|% {if (!$As) {$9=sc.exe start $_; $As=@(get-process -name $_ -ea 0|% {$_})[0]}}
 function M ($1,$2,$3) {$M."G`etMethod"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H += M "AllocHG`lobal" $I $_}
 M "WriteInt`Ptr" ($P,$P) ($H[0],$As.Handle); $A1.f1=131072; $A1.f2=$Z; $A1.f3=$H[0]; $A2.f1=1; $A2.f2=1; $A2.f3=1; $A2.f4=1
 $A2.f6=$A1; $A3.f1=10*$Z+32; $A4.f1=$A3; $A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false)
 $Run=@($null, "powershell -win 1 -nop -c iex `$env:R; # $id", 0, 0, 0, 0x0E080600, 0, $null, ($A4 -as $T[4]), ($A5 -as $T[5]))
 F 'CreateProcess' $Run; return}; $env:R=''; rp $key $id -force; $priv=[diagnostics.process]."GetM`ember"('SetPrivilege',42)[0]
 'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege' |% {$priv.Invoke($null, @("$_",2))}
 $HKU=[uintptr][uint32]2147483651; $NT='S-1-5-18'; $reg=($HKU,$NT,8,2,($HKU -as $D[9])); F 'RegOpenKeyEx' $reg; $LNK=$reg[4]
 function L ($1,$2,$3) {sp 'HKLM:\Software\Classes\AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}' 'RunAs' $3 -force -ea 0
  $b=[Text.Encoding]::Unicode.GetBytes("\Registry\User\$1"); F 'RegSetValueEx' @($2,'SymbolicLinkValue',0,6,[byte[]]$b,$b.Length)}
 function Q {[int](gwmi win32_process -filter 'name="explorer.exe"'|?{$_.getownersid().sid-eq$NT}|select -last 1).ProcessId}
 $11bug=($((gwmi Win32_OperatingSystem).BuildNumber)-eq'22000')-AND(($cmd-eq'file:')-OR(test-path -lit $cmd -PathType Container))
 if ($11bug) {'System.Windows.Forms','Microsoft.VisualBasic' |% {[Reflection.Assembly]::LoadWithPartialName("'$_")}}
 if ($11bug) {$path='^(l)'+$($cmd -replace '([\+\^\%\~\(\)\[\]])','{$1}')+'{ENTER}'; $cmd='control.exe'; $arg='admintools'}
 L ($key-split'\\')[1] $LNK ''; $R=[diagnostics.process]::start($cmd,$arg); if ($R) {$R.PriorityClass='High'; $R.WaitForExit()}
 if ($11bug) {$w=0; do {if($w-gt40){break}; sleep -mi 250;$w++} until (Q); [Microsoft.VisualBasic.Interaction]::AppActivate($(Q))}
 if ($11bug) {[Windows.Forms.SendKeys]::SendWait($path)}; do {sleep 7} while(Q); L '.Default' $LNK 'Interactive User'
'@; $V='';'cmd','arg','id','key'|%{$V+="`n`$$_='$($(gv $_ -val)-replace"'","''")';"}; sp $key $id $($V,$code) -type 7 -force -ea 0
 start powershell -args "-win 1 -nop -c `n$V `$env:R=(gi `$key -ea 0).getvalue(`$id)-join''; iex `$env:R" -verb runas
}; $A=,$env:1-split'"([^"]+)"|([^ ]+)',2|%{$_.Trim(' ')}; RunAsTI $A[1] $A[2]; #:RunAsTI lean & mean snippet by AveYo, 2023.07.06

: end batch / begin PowerShell #>

$Host.UI.RawUI.WindowTitle = "Disable Defender (AME Wizard) | he3als"

$paths = @(
	"$env:ProgramData\Microsoft\Windows Defender",
	"$env:ProgramFiles\Windows Defender",
	"$env:ProgramFiles\Windows Defender Advanced Threat Protection"
)

function RenamePaths {
	[CmdletBinding()]
	param (
		[Switch]$Revert
	)
	foreach ($path in $paths) {
		$files = Get-ChildItem -Path $path -File -Recurse
		foreach ($file in $files) {
			if ($Revert) {$newName = $file.Name -replace '\.old$'} else {$newName = $file.Name + ".old"}
			Rename-Item -Path $file.FullName -NewName $newName -Force -EA SilentlyContinue
		}
	}
}

if (!($AfterRestart)) {
	if ((Get-Service -Name "Schedule" -EA SilentlyContinue).Status -ne 'Running') {
		Write-Host "The Task Scheduler service isn't running or doesn't exist." -ForegroundColor Red
		Write-Host "Press any key to exit... " -NoNewLine
		$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
	}
	
	Write-Host "This will disable Defender a different way to work around AME Wizard issues, Windows will restart after it's finished." -ForegroundColor Yellow
	pause; Write-Host ""

	Write-Warning "Renaming Defender files..."
	RenamePaths

	Write-Warning "Registring scheduled task to disable Defender properly next reboot..."
	$action = New-ScheduledTaskAction -Execute "$env:windir\System32\cmd.exe" -Argument '/c "C:\Windows\ameFix.cmd" /afterRestart'
	$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
	$trigger = New-ScheduledTaskTrigger -AtLogon
	Register-ScheduledTask -TaskName "RemoveDefenderAMEWizardTempFix" -Trigger $trigger -Action $action -Settings $settings -User $env:USERNAME -RunLevel Highest -Force | Out-Null

	Write-Warning "Restarting in 5 seconds..."
	Start-Sleep 5; Restart-Computer -Force
	# in case restarting fails somehow
	pause; exit
} else {
	Write-Warning "Unregistering scheduled task..."
	Unregister-ScheduledTask -TaskName "RemoveDefenderAMEWizardTempFix" -Confirm:$false | Out-Null

	Write-Warning "Un-renaming Defender files..."
	RenamePaths -Revert
	
	Write-Warning "Disabling services and drivers..."
	$services = @(
		"WinDefend",
		"WdNisSvc",
		"WdNisDrv",
		"Sense",
		"WdFilter",
		"WdBoot"
	)
	foreach ($service in $services) {
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$service" -Name "Start" -Value 4
	}
	
	Write-Host "`nCompleted! Run the 'Preparing Installation' in AME Wizard." -ForegroundColor Green
	Write-Host "Press any key to exit... " -NoNewLine
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
	Start-Process -FilePath 'cmd.exe' -ArgumentList '/c timeout.exe /t 2 /nobreak > nul & del /f /q %windir%\ameFix.cmd' -WindowStyle Hidden
	exit
}