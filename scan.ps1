$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$checks = [System.Collections.Generic.List[object]]::new()
function Add-Check($id, $name, $category, $status, $detail, $recommendation, $settings) {
    $checks.Add([pscustomobject]@{id=$id;name=$name;category=$category;status=$status;detail=$detail;recommendation=$recommendation;settings=$settings})
}
function Inspect($id, $name, $category, $recommendation, $settings, [scriptblock]$probe) {
    try { $result = & $probe; Add-Check $id $name $category $result.status $result.detail $recommendation $settings }
    catch { Add-Check $id $name $category 'unknown' 'Windows did not provide enough information. This check may need administrator access or may not be supported on this device.' $recommendation $settings }
}
Inspect 'firewall' 'Windows Firewall' 'Security' 'Keep the firewall enabled for Domain, Private, and Public networks. Review managed policies with your administrator.' 'windowsdefender://network' {
    $p = @(Get-NetFirewallProfile); if ($p.Count -ne 3) { throw 'Incomplete result' }
    @{status=$(if (@($p | Where-Object { -not $_.Enabled }).Count) {'attention'} else {'pass'});detail=($p | ForEach-Object { "$($_.Name): $(if ($_.Enabled) {'on'} else {'off'})" }) -join ' | '}
}
Inspect 'antivirus' 'Antivirus protection' 'Security' 'Open Windows Security and confirm that your chosen antivirus provider is active and up to date. A third-party antivirus can legitimately disable Defender.' 'windowsdefender://threat' {
    $providers = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct)
    try { $mp = Get-MpComputerStatus } catch { $mp = $null }
    if ($mp -and $mp.AntivirusEnabled -and $mp.RealTimeProtectionEnabled) { @{status='pass';detail='Microsoft Defender antivirus and real-time protection are enabled.'} }
    elseif ($providers.Count) { @{status='review';detail='Registered providers: ' + (($providers | ForEach-Object displayName) -join ', ') + '. Provider registration alone does not confirm active protection.'} }
    else { @{status='unknown';detail='No antivirus status could be confirmed.'} }
}
Inspect 'encryption' 'System drive encryption' 'Security' 'Review BitLocker or Device encryption. Before enabling encryption, save your recovery key somewhere you can access if this PC is locked.' 'ms-settings:deviceencryption' {
    $v = Get-BitLockerVolume -MountPoint $env:SystemDrive
    if ($null -eq $v) { throw 'Missing volume' }
    @{status=$(if ([string]$v.ProtectionStatus -eq 'On') {'pass'} else {'attention'});detail="System drive protection: $($v.ProtectionStatus). Encryption: $($v.VolumeStatus)."}
}
Inspect 'secureboot' 'Secure Boot' 'Security' 'Review Secure Boot support in System Information. Firmware changes depend on the PC manufacturer and should be planned alongside disk encryption recovery.' 'msinfo32' {
    $enabled = Confirm-SecureBootUEFI
    @{status=$(if ($enabled) {'pass'} else {'attention'});detail=$(if ($enabled) {'Secure Boot is enabled.'} else {'Secure Boot is disabled.'})}
}
Inspect 'uac' 'User Account Control' 'Security' 'Keep User Account Control enabled with prompts for administrator actions.' 'uac' {
    $v = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    if ($null -eq $v.EnableLUA -or $null -eq $v.ConsentPromptBehaviorAdmin) { throw 'Missing values' }
    @{status=$(if ($v.EnableLUA -eq 1 -and $v.ConsentPromptBehaviorAdmin -ne 0) {'pass'} else {'attention'});detail=$(if ($v.EnableLUA -ne 1) {'User Account Control is disabled.'} elseif ($v.ConsentPromptBehaviorAdmin -eq 0) {'Administrator elevation is configured without a consent prompt.'} else {'User Account Control and administrator elevation prompts are enabled.'})}
}
Inspect 'rdp' 'Remote Desktop' 'Security' 'Leave Remote Desktop off unless you use it. If required, restrict access to trusted users and networks.' 'ms-settings:remotedesktop' {
    $v = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    if ($null -eq $v.fDenyTSConnections) { throw 'Missing value' }
    @{status=$(if ($v.fDenyTSConnections -eq 1) {'pass'} else {'review'});detail=$(if ($v.fDenyTSConnections -eq 1) {'Incoming Remote Desktop connections are disabled.'} else {'Incoming Remote Desktop connections are enabled. Confirm this is intentional.'})}
}
Inspect 'smb1' 'Legacy SMBv1 protocol' 'Security' 'Keep the SMBv1 server protocol disabled. Legacy equipment may depend on it; check compatibility before changing this setting. This check covers the server setting only.' 'optionalfeatures' {
    $v = Get-SmbServerConfiguration
    if ($null -eq $v.EnableSMB1Protocol) { throw 'Missing value' }
    @{status=$(if ($v.EnableSMB1Protocol) {'attention'} else {'pass'});detail=$(if ($v.EnableSMB1Protocol) {'The legacy SMBv1 server protocol is enabled.'} else {'The legacy SMBv1 server protocol is disabled. Client features are not assessed.'})}
}
Inspect 'updates' 'Windows update history' 'Security' 'Open Windows Update and check for updates. Install history cannot establish whether all available updates are installed.' 'ms-settings:windowsupdate' {
    $last = Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if (-not $last) { throw 'No update history' }
    @{status='review';detail="Latest hotfix reported by Windows: $($last.HotFixID), installed $($last.InstalledOn.ToString('yyyy-MM-dd')). Check Windows Update for current availability."}
}
Inspect 'advertising' 'Advertising identifier' 'Privacy' 'Review whether apps may use your advertising ID to show personalized ads.' 'ms-settings:privacy-general' {
    $v = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
    if ($null -eq $v.Enabled) { throw 'Missing value' }
    @{status=$(if ($v.Enabled -eq 0) {'pass'} else {'review'});detail=$(if ($v.Enabled -eq 0) {'The current user advertising ID is disabled.'} else {'The current user advertising ID is enabled.'})}
}
Inspect 'location' 'Location access' 'Privacy' 'Review which apps need location. Disabling it can affect maps, automatic time zones, and Find my device.' 'ms-settings:privacy-location' {
    $v = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
    if ($v.Value -notin @('Allow','Deny')) { throw 'Unknown consent value' }
    @{status=$(if ($v.Value -eq 'Deny') {'pass'} else {'review'});detail="Device location permission: $($v.Value). Individual app permissions require a separate review."}
}
[pscustomobject]@{scannedAt=[DateTime]::UtcNow.ToString('o');checks=@($checks.ToArray());scope='Local Windows configuration checks. No network vulnerability scan, malware scan, or compliance certification.'} | ConvertTo-Json -Depth 6 -Compress

