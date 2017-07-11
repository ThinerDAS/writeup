# 0ctf final IDEA exp

The critical part is to recover the encryption key.

We use a traverser that take a traversing program as input and traverse and finally find a satisfying route, and print the cared nodes on the way.

Then we use some method to recognize the 16-bit adder & xorer along the whole way. The multiplier is hard to recognize, so it is skipped.

Naive traversing is not viable since for one adder, there are two xorer there (look at the graph of IDEA), and it is hard to recognize.

Therefore, we take the idea of Von Neumann, treating the program as data, and put the traversing logic as a serializable program, and write an interpreter to execute the program. Then we finally recover most of the key. And bruteforcing the other bits.