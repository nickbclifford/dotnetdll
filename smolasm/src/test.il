assembly hello_world

extern mscorlib v6.0.0.0

uint enum Hello {
    ASDF
}

class TestAttribute extends [mscorlib]System.Attribute implements [mscorlib]System.Collections.IEnumerable, [mscorlib]System.IDisposable {
    public method void constructor() {
        ldarg this
        call [mscorlib]System.Object.constructor()
        ret
    }
}

interface IDoThing {
    public method void Yeet()
}

public class Foo {
    private protected field string hi

    public method void constructor() {
        ldarg this
        call [mscorlib]System.Object.constructor()
        ret
    }

    public static method void Main([string] args) entrypoint {
        ldstr "hello, world"
        call [mscorlib]System.Console.WriteLine(string)
        ret
    }

    public static method void Test() {
        uint counter
        ---
        ldi32 0
        stloc counter
    loop:
        ldstr "loop iteration {0}"
        ldloc counter
        box
        call [mscorlib]System.Console.WriteLine(string, object)
        jump loop
    }
}
