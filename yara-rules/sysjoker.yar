rule syjoker {
   meta:
     author = "CD_R0M_"
     description = "Windows sysjoker malware"
     hash = "d90d0f4d6dad402b5d025987030cc87c"
     HundredDaysofYARA = "Day 11"
    
  strings:
    $masq = "igfxCUIService.exe" nocase wide
	
    $txt1 = "txc1.txt" nocase
    $txt2 = "txc2.txt" nocase
	
    $tmp = /\\temp..\.txt/ nocase
	
  condition:
    uint16(0) == 0x5A4D and $masq and all of ($txt*) and $tmp
}
