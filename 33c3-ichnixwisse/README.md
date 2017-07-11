# ichnixwisse

Root of all evil:
```C++

int read_int() {
    char buf[11];
    read(buf, 11);
    CHECK(buf[10] == '\n');
    for (int i = 0; i < 10; ++i)
        CHECK(isdigit(buf[i]));
    int res;
    sscanf(buf, "%d", &res);
    return res;
}

```

`sscanf` can accept *0000000001* and *4294967297* and *8589934593* as number 1. However, it introduces different entropy to the random number generator. By specifying everytime the number is inputed, we can direct the graph check flow. Even if we don't have a perfect graph coloring (actually we can fail for 1/3 of the edges, however, the introduced entropy) we can decide which edge it checks by sending different representation of colors. Every wave you have 3*3=9 ways of injecting different entropy, therefore by applying simple mathematics we have: chance of passing graph test is (1-(1/3)^9)^300=0.984, which is even higher than the chance of a graph coloring being rejected in the first wave (2/3). The attack is viable.


