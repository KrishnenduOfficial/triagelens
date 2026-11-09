rule powershell_encoded_command_text {
    meta:
        id = "triagelens.powershell_encoded_command_text"
        author = "TriageLens Contributors"
        source = "https://github.com/KrishnenduOfficial/triagelens"
        revision = "1"
        license = "MIT"
        mitre_attack = "T1059.001,T1027"
    strings:
        $shell = "powershell" ascii wide nocase
        $flag = "-encodedcommand" ascii wide nocase
    condition:
        all of them
}
