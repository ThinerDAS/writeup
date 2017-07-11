# peropdo

Two vulnerabilities:

You can send an oversized name so that you controlled the whole bss.

You can roll over large amount of dices so that the random number overflow the whole stack.

One of the easiest ways to exploit is: use the second to overwrite ebp, and use the parent function ret to set esp to ebp, which becomes a bss address.

Here comes the question: how to make sure the dice rolls out to be the preferred value? Actually the name is the seed of the random number generator. We can bruteforce and see whether the random value is preferred. This involves patching a shellcode onto the main function so that we can run native code and get the good seed faster.

Finally we can ROP.