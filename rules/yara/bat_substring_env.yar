rule BAT_Begin_Substring_Env {
    meta:
        id = "elceef.bat_begin_substring_env"
        author = "Marcin Ulikowski"
        source = "https://github.com/elceef/yara-rulz/blob/main/rules/Suspicious_BAT.yara"
        revision = "2023-06-02; triagelens-metadata-1"
        license = "MIT"
        mitre_attack = "T1027,T1059.003"
    strings:
        $echo = "@echo off"
        $substr = { 3a 7e ( 3? 2c 3? | 2d 3? 2c 3? | 3? 2c 2d 3? | 3? 3? 2c 3? | 2d 3? 3? 2c 3? | 3? 3? 2c 2d 3? ) 25 }
    condition:
        $echo in (0..4) and $substr in (10..100)
}
