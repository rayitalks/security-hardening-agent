param([ValidateSet('list','inspect')][string]$Mode='list',[string]$Id='')
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
Import-Module Hyper-V
if ($Mode -eq 'list') {
    $items=@(Get-VM | Select-Object -First 200 | ForEach-Object { @{id=$_.Id.ToString();name=$_.Name;state=$_.State.ToString()} })
    ConvertTo-Json -InputObject $items -Depth 4 -Compress
    exit
}
$vm=Get-VM -Id ([guid]$Id)
$controls=@{}
$details=@{generation=$vm.Generation;state=$vm.State.ToString();memoryMB=([math]::Round($vm.MemoryStartup/1MB));vcpus=$vm.ProcessorCount;dynamicMemory=$vm.DynamicMemoryEnabled;memoryMaximum=$vm.MemoryMaximum}
try {$firmware=Get-VMFirmware -VM $vm; $controls.secureBoot=($firmware.SecureBoot.ToString() -eq 'On')} catch {}
try {$security=Get-VMSecurity -VM $vm; $controls.tpm=[bool]$security.TpmEnabled;$details.shielded=[bool]$security.Shielded} catch {}
try {$cpu=Get-VMProcessor -VM $vm;$controls.nestedVirtualization=[bool]$cpu.ExposeVirtualizationExtensions} catch {}
try {$details.checkpointCount=@(Get-VMSnapshot -VM $vm).Count} catch {}
try {
    $nics=@(Get-VMNetworkAdapter -VM $vm)
    $switches=@(Get-VMSwitch | Where-Object {$_.SwitchType -eq 'External'} | Select-Object -ExpandProperty Id)
    $controls.bridgedNetwork=(@($nics | Where-Object {$_.SwitchId -in $switches}).Count -gt 0)
} catch {}
# Enhanced-session clipboard, console endpoint ACLs, device assignment and host shares require separate evidence.
$result=@{schema='sha-vm-evidence-v1';provider='hyperv';id=$vm.Id.ToString();name=$vm.Name;controls=$controls;details=$details}
ConvertTo-Json -InputObject $result -Depth 6 -Compress
