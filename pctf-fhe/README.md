# FHE

The problem is mathematic.

```python
class FHE(object):
    def __init__(self, n):
        self.n = n
        self.t = random_vector(n)

    def key(self):
        return self.t

    def encrypt(self, m):
        n = self.n
        t = self.t
        rows = [random_vector(n) for _ in range(n-1)]
        v = t[:-1] * matrix(rows)
        u = vector([t[-1]^(-1) * (m * t[i] - v[i]) for i in range(n)])
        rows.append(u)
        C = matrix(rows)
        return C
```

Actually, if you are familiar with matrix algebra, it is not hard to verify that: the encryption algorithm just output a matrix('s transpose) with eigenvector `self.t` and eigenvalue `m`. (To verify, multiply transpose of C with t)

Also, although solving an eigenvector/eigenvalue is not easy, especially in a finite field, when two matrices A & B *share* an eigenvector, the eigenvector is in the kernel of (AB-BA). Kernel is very easy to solve (It is as easy as solving a linear equation.)

Therefore, after getting the eigenvector, we can go next to the eigenvalues, and it seems that in order to solve the m, knowing all the eigenvalues, we only need to do a discrete logarithm on the remainder field, and do some easy algebraic operations.

