rule ContainsHelloWorld {
    strings:
        $hello = "hello"
    condition:
        $hello
}

