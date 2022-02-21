assembly hello_world

extern mscorlib v6.0.0.0

public class Foo extends System.Object {
    public method void constructor() {
        ldarg this
        call [mscorlib]System.Object.constructor()
        ret
    }

    public static method void Main([string] args) {
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
