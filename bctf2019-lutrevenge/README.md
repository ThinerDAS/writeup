# lut-revenge

I am not sure why this problem is solved by fewer teams though I feel lucky for that :D

Frankly speaking I did not expect to meet this difficulty of crypto in such a nasty re problem, considering that my crypto skill is scarce for the 2019 year.

## Solution

The important function is `enc` and by reasonable assumption we know that it is xor of 10 values of 80 bits, which are chosen from 10 arrays respectively. (See ccode.c / check.py for strict description)

So we can extract the lookup table in a blackbox manner. `ccode.c` extracts the lookup table and verify that our assumption is correct.

Then the problem is about solving. Meet-in-the-middle does not quite work for 2^80 for reasonable calculation power, we believe. Notice that each lookup table `256x80` matrix has a low rank of 9, we use Gaussian Elimination - namely we use `Matrix.echelon_form()` (goddess how is it pronounced ..) for a good matrix that is helpful for later DFS search. After gaussian elimination we plainly do DFS for the flag. `check.sage` / `check.py` demonstrates the process.

## Run

```
gcc -O3 ccode.c -o ccode -fPIE -pie  && ./ccode
sage check.sage
```