rule netmonitor_elf {
    meta:
        description = "Обнаружение netmonitor по magic-числу ELF"
    strings:
        $elf_magic = { 7F 45 4C 46 }  // Magic-число ELF
    condition:
        $elf_magic at 0
}

rule netmonitor_hash {
    meta:
        description = "Обнаружение по MD5-хешу"
    strings:
        $hash = "cf2444f470a6fb908cdae55f31da61e" ascii wide  // Реальный хеш
    condition:
        $hash
}

rule netmonitor_strings {
    meta:
        description = "Обнаружение по уникальным строкам"
    strings:
        $str1 = "Ошибка настройки интерфейса!" fullword
        $str2 = "ПРЕВЫШЕНИЕ:" fullword
    condition:
        any of ($str*)
}

rule netmonitor_hex {
    meta:
        description = "Обнаружение по hex-паттернам"
    strings:
        $hex1 = { 73 69 67 6E 61 6C }  // "signal" в hex
        $hex2 = { 53 49 4F 43 47 49 46 }  // "SIOCGIF" в hex
    condition:
        any of them
}

rule netmonitor_xor {
    meta:
        description = "Обнаружение по XOR-строке"
    strings:
        $xor_str = "enp0s3" xor  // Имя интерфейса из кода
    condition:
        $xor_str
}

rule netmonitor_size {
    meta:
        description = "Обнаружение по размеру файла"
    condition:
        filesize == 53480  // Точный размер в байтах
}