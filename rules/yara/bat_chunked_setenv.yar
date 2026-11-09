rule BAT_Chunked_Payload_SetEnv {
    meta:
        id = "elceef.bat_chunked_payload_setenv"
        author = "Marcin Ulikowski"
        source = "https://github.com/elceef/yara-rulz/blob/main/rules/Suspicious_BAT.yara"
        revision = "2023-05-05; triagelens-metadata-1"
        license = "MIT"
        mitre_attack = "T1027,T1059.003"
    strings:
        $echo = "@echo off"
        $set = { ( 0d 0a | 26 20 ) 73 65 74 20 22 [10] 3d [2-6] 22 }
    condition:
        $echo in (0..4) and #set > 10
}
