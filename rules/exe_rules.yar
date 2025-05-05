rule HelloWorld
{
    strings:
        $msg = "hello worlds"
    condition:
        $msg
}
