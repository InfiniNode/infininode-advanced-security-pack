rule ExampleMalware {
    strings:
        $a = "malicious_string"
    condition:
        $a
} 