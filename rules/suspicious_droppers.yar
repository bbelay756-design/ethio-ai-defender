/*
    ETHIO-AI Defender - Defensive Static YARA Rules
    Category: Dropper & Egress Indicators
*/

rule Suspicious_Powershell_Encoded_Command
{
    meta:
        description = "Detects hidden or encoded PowerShell invocation parameters"
        author = "ETHIO-AI Defender Threat Research"
        severity = "HIGH"
        category = "COMMAND_EXECUTION"
    strings:
        $ps1 = "powershell" ascii nocase
        $enc1 = "-enc" ascii nocase
        $enc2 = "-encodedcommand" ascii nocase
        $nop = "-nop" ascii nocase
        $byp = "-bypass" ascii nocase
        $iex = "IEX" ascii
        $dl = "DownloadString" ascii nocase
    condition:
        $ps1 and ($enc1 or $enc2 or $nop or $byp or $iex or $dl)
}

rule Suspicious_Network_Egress_Primitives
{
    meta:
        description = "Detects combination of network download APIs and execution"
        author = "ETHIO-AI Defender Threat Research"
        severity = "MEDIUM"
        category = "NETWORK"
    strings:
        $net1 = "URLDownloadToFile" ascii
        $net2 = "InternetOpen" ascii
        $exec1 = "WinExec" ascii
        $exec2 = "ShellExecute" ascii
        $exec3 = "CreateProcess" ascii
    condition:
        ($net1 or $net2) and ($exec1 or $exec2 or $exec3)
}
