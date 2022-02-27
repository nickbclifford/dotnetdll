assembly hello_world

uint enum Hello {
    ASDF
}

interface IDoThing {
    public method Yeet() -> void
}

public class Foo {
    private protected field string myString

    public property string CapitalizedString {
        get {
            load argument this
            load field string Foo::myString
            call string::ToUpper() -> string
            return
        }
    }

    public static method Main([string] args) -> void @entrypoint {
        load string "hello, world"
        call static [mscorlib]System.Console::WriteLine(string) -> void
        call static Foo::Test() -> void
        return
    }

    public static method Test() -> void {
        locals init {
            uint counter
        }

    loop:
        load string "loop iteration {0}"
        load local counter
        box uint
        call static [mscorlib]System.Console::WriteLine(string, object) -> void
        load local counter
        load int 1
        add
        store local counter
        branch loop
        return
    }
}
