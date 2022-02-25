assembly hello_world

extern mscorlib v6.0.0.0

uint enum Hello {
    ASDF
}

interface IDoThing {
    public method void Yeet()
}

public class Foo {
    private protected field string hi

    public method void constructor() {
        load argument this
        call [mscorlib]System.Object.constructor()
        return
    }

    public static method void Main([string] args) entrypoint {
        load string "hello, world"
        call [mscorlib]System.Console.WriteLine(string)
        return
    }

    public static method void Test() {
        locals {
            uint counter
        }

        load int 0
        store local counter
    loop:
        load string "loop iteration {0}"
        load local counter
        box uint
        call [mscorlib]System.Console.WriteLine(string, object)
        branch loop
    }
}
