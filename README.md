# DBIdbg

A x86 Linux debugger that can be used to debug things normally too complex for debuggers.


## Motivation

To speed up the debugging process (especially debugging black-box/RE) by allowing for debug breakpoints to be set on much more abstract things than normal debuggers allow, such as:

* Count the number of times this tight loop is run
* Break whenever a string with the contents "AAAA" is loaded into rdi
