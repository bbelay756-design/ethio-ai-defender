/*
    ETHIO-AI Defender - Defensive Static YARA Rules
    Category: PE Structure & Header Indicators
*/

rule Suspicious_Packed_Section_Name
{
    meta:
        description = "Detects common packer, crypter, or protector section names in PE binaries"
        author = "ETHIO-AI Defender Threat Research"
        severity = "MEDIUM"
        category = "PE_STRUCTURE"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX2" ascii
        $aspack = ".aspack" ascii
        $themida = ".themida" ascii
        $vmp = ".vmp0" ascii
        $mpress = ".mpress1" ascii
        $packed = ".packed" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Suspicious_WplusX_Indicator
{
    meta:
        description = "Identifies potential executable and writable memory allocation primitives"
        author = "ETHIO-AI Defender Threat Research"
        severity = "HIGH"
        category = "MEMORY"
    strings:
        $api1 = "VirtualAlloc" ascii
        $api2 = "VirtualProtect" ascii
        $api3 = "WriteProcessMemory" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
