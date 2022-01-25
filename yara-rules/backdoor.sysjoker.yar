rule RAT__Sysjoker_Dropper_Win : Backdoor {
  meta:
    author = "@_lubiedo"
    date   = "13-01-2022"
    hash   = "61df74731fbe1eafb2eb987f20e5226962eeceef010164e41ea6c4494a4010fc"
    reference = "https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/"
  strings:
    $s00 = "https://github.url-mini.com/msg.zip" fullword
    $s01 = "\\recoveryWindows.zip" fullword nocase
    $s02 = "powershell.exe Invoke-WebRequest -Uri" nocase
    $s03 = "';Write-Output \"Time taken : $((Get - Date).Subtract($start_time).Seconds) second(s)\"" fullword nocase
  condition:
    filesize < 400KB and uint16be(0) == 0x4D5A and all of ($s*)
}

rule RAT__Sysjoker_Backdoor_Win : Backdoor {
  meta:
    author = "@_lubiedo"
    date   = "13-01-2022"
    hash   = "1ffd6559d21470c40dcf9236da51e5823d7ad58c93502279871c3fe7718c901c"
    reference = "https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/"
  strings:
    $s00 = "Set-Cookie:\\b*{.+?}\\n" fullword wide nocase
    $s02 = /\\(txc|temp[osi])[0-9]\.txt/ nocase
    $s03 = "wmic path win32_physicalmedia get SerialNumber"
    $s04 = "&user_token=8723478873487" fullword nocase
    $s05 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0" fullword wide
    $s06 = "IGFXCUISERVICE.EXE" fullword wide
  condition:
    filesize < 500KB and uint16be(0) == 0x4D5A and all of ($s*)
}

rule RAT__Sysjoker_Backdoor_macOS : Backdoor {
  meta:
    author = "@_lubiedo"
    date   = "13-01-2022"
    hash   = "1a9a5c797777f37463b44de2b49a7f95abca786db3977dcdac0f79da739c08ac"
    reference = "https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/"
  strings:
    $s00 = "https://drive.google.com/uc?export=download&id=1W64PQQxrwY3XjBnv_QAeBQu-ePr537eu" fullword
    $s01 = "updateMacOS" fullword nocase
    $s02 = "&user_token=987217232" fullword
    $s03 = "/Library/LaunchAgents/com.apple.update.plist" fullword
    $s04 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15" fullword
  condition:
    filesize < 500KB and uint32be(0) == 0xCAFEBABE and all of ($s*)
}

rule RAT__Sysjoker_Backdoor_Linux : Backdoor {
  meta:
    author = "@_lubiedo"
    date   = "13-01-2022"
    hash   = "1a9a5c797777f37463b44de2b49a7f95abca786db3977dcdac0f79da739c08ac"
    reference = "https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/"
  strings:
    $s00 = "ip address | awk '/ether/{print $2}'" fullword
    $s01 = "uname -mrs" fullword
    $s02 = "&user_token=987217232" fullword
    $s03 = "before addToStatup" fullword
    $s04 = "ifconfig | grep -v 127.0.0.1 | grep -E \"inet ([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})\" | awk '{print $2}'" fullword
  condition:
    filesize < 2MB and uint32be(0) == 0x7F454C46 and all of ($s*)
}

rule RAT__Sysjoker_Backdoor_Macos_generator : Backerdoor {
  meta:
    	author = "jackzhou"
      date = "2022-01-24"
      description = "hunt sysjoker"
      hash0 = "e06e06752509f9cd8bc85aa1aa24dba2"
      sample_filetype = "exe"
      yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
  strings:
      $string1 = "__Znwm"
      $string4 = " value_t::array "
      $string5 = "' after '/'"
      $string9 = "/Users/"
      $string10 = "___cxa_end_catch"
      $string11 = "<plist version"
      $string12 = "___stack_chk_guard"
      $string14 = "iterator does not fit current value"
      $string15 = "_system"
      $string16 = "chmod 0777 '"
  condition:
      all of them
}

rule RAT__mal_sysjoker_macOS {
    meta:
        description = "Identify string artifacts from the SysJoker macOS backdoor."
        author = "@shellcromancer <root@shellcromancer.io>"
        version = "0.1"
        date = "2022-01-13"
        reference = "https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/"
        reference = "https://objective-see.com/blog/blog_0x6C.html"
        sha256 = "1a9a5c797777f37463b44de2b49a7f95abca786db3977dcdac0f79da739c08ac"
    strings:
        $s1 = "1W64PQQxrwY3XjBnv_QAeBQu-ePr537eu" // Google Sheets ID
        $s2 = "welcome to extenal app"
        $s3 = "updateMacOs"
        $s4 = "/Users/mac/Desktop/test/test/json.hpp"
    condition:
        (uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint32(0) == 0xcafebabe or uint32(0) == 0xbebafeca)
        and any of them
}

rule RAT__mal_sysjoker_macOS_cmds {
    meta:
        description = "Identify shell commands in the SysJoker macOS backdoor."
        author = "@shellcromancer <root@shellcromancer.io>"
        version = "0.1"
        date = "2022-01-13"
        reference = "https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/"
        reference = "https://objective-see.com/blog/blog_0x6C.html"
        sha256 = "1a9a5c797777f37463b44de2b49a7f95abca786db3977dcdac0f79da739c08ac"
    strings:
        $s1 = ">/dev/null 2>&1 &"
        $s2 = "chmod 0777"
        $s3 = "unzip -o"
        $s4 = "whoami"
    condition:
        all of them
}

rule RAT__sysjoker_Linux_cmds_hunt {
    meta:
        description = "Identify shell commands in the SysJoker Linux backdoor."
        author = "jackzhou"
        version = "0.1"
        date = "2022-01-24"
        hash = "5e11432c30783b184dc2bf27aa1728b4"
        reference = "https://objective-see.com/blog/blog_0x6C.html"
        sha256 = "bd0141e88a0d56b508bc52db4dab68a49b6027a486e4d9514ec0db006fe71eed"
    strings:
        $s1 = "@reboot"
        $s2 = "/.Library/SystemServices/updateSystem"
        $s3 = "crontab -l | egrep -v "
        $s4 = "cut -c -80"
    condition:
        all of them
}