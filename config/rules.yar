rule c99_webshell {
    meta:
        description = "C99 Shell Detection"
    strings:
        $c99 = "<?php @eval($_POST['cmd']); ?>"
        $login = "C99shell"
    condition:
        any of them
}

rule r57_shell {
    meta:
        description = "R57 Shell Detection"
    strings:
        $r57 = "eval(gzinflate(base64_decode('"
    condition:
        $r57
}

rule filesman_shell {
    meta:
        description = "FilesMan Shell Detection"
    strings:
        $filesman = "FilesMan"
        $auth = "if(md5($_POST['pass'])=="
    condition:
        all of them
}
