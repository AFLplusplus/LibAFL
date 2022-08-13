# Baby Gramatron

This fuzzer shows how to implement grammar-aware fuzzing. [Gramatron](https://github.com/HexHive/Gramatron) uses grammar automatons in conjunction with aggressive mutation operators to synthesize complex bug triggers. `auto.json` records grammar automaton of php,which is corresponding to `libafl::generators::Automaton`and serialized into `auto.postcard`. `libafl::generators::gramatron` will generate valid grammar sequences using `Automaton` and then pass them into `harness`. The function of `harness` is to print the original input.

When you use `cargo run`, You may see output as follows:
```
b=mlhs_node.isz(c,c, )
d=false.keyword__FILE__(c,b,a,b)
a=select.Jan(d)
a=first.literal( )
b=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,nil].DomainError(c)
next a
b=Oo.gsub(a,d,b)
d=0.hex( )
```