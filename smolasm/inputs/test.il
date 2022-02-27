assembly hello_world

uint enum Hello {
    ASDF
}

interface IDoThing {
    public method void Yeet()
}

public class Foo {
    private protected field string myString

    public property string CapitalizedString {
        get {
            load argument this
            load field string Foo::myString
            call string string::ToUpper()
            return
        }
    }

    public static method void Main([string] args) entrypoint {
        load string "hello, world"
        call static void [mscorlib]System.Console::WriteLine(string)
        call static void Foo::Test()
        return
    }

    public static method void Test() {
        locals init {
            uint counter
        }

    loop:
        load string "loop iteration {0}"
        load local counter
        box uint
        call static void [mscorlib]System.Console::WriteLine(string, object)
        load local counter
        load int 1
        add
        store local counter
        branch loop
        return
    }
}
