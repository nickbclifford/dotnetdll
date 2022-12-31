assembly oop

extern mscorlib

public class Greeter {
    protected field string greeting

    public method .ctor(string input) -> void @specialname @rtspecialname {
        load argument this
        call [mscorlib]System.Object::.ctor() -> void
        load argument this
        load argument input
        store field string Greeter::greeting
        return
    }

    public method Greeting() -> string @virtual {
        load string "Hello, {0}"
        load argument this
        load field string Greeter::greeting
        call static string::Format(string, object) -> string
        return
    }

    public static method Main([string] args) -> void @entrypoint {
        locals init {
            string input
        }

        load argument args
        load int 0
        load element string
        store local input
        load local input
        new Greeter(string)
        call virtual Greeter::Greeting() -> string
        call static [mscorlib]System.Console::WriteLine(string) -> void
        load local input
        new ExcitedGreeter(string)
        call virtual Greeter::Greeting() -> string
        call static [mscorlib]System.Console::WriteLine(string) -> void
        return
    }
}

public class ExcitedGreeter extends Greeter {
    public method .ctor(string input) -> void @specialname @rtspecialname {
        load argument this
        load argument input
        call Greeter::.ctor(string) -> void
        return
    }

    public method Greeting() -> string @virtual {
        load string "Hello, {0}!!"
        load argument this
        load field string Greeter::greeting
        call static string::Format(string, object) -> string
        return
    }
}
