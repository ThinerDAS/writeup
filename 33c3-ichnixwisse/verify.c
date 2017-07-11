#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>

#define CHECK(x) do { \
    if (!(x)) { printf("Big nope at line %d\n", __LINE__); abort(); } }while(0)

struct Edge {
    int x, y;
} *edges;
int num_nodes, num_edges;

SHA_CTX ctx;

void read_graph(const char* graph_file) {
    FILE* f = fopen(graph_file, "r");
    CHECK(f);
    CHECK(2 == fscanf(f, "p edge %d %d\n", &num_nodes, &num_edges));
    edges = calloc(num_edges, sizeof *edges);
    for (int i = 0; i < num_edges; ++i)
        CHECK(2 == fscanf(f, "e %d %d\n", &edges[i].x, &edges[i].y));
}

void read(char* buf, int cnt) {
    CHECK(cnt == fread(buf, 1, cnt, stdin));
    SHA1_Update(&ctx, buf, cnt);
}

void read_hash(char* buf) {
    read(buf, SHA_DIGEST_LENGTH);
}

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

int randomc(int mod) {
    SHA_CTX ctx2 = ctx;
    unsigned char buf[SHA_DIGEST_LENGTH];
    SHA1_Final(buf, &ctx2);
    int res = 0;
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i)
        res = ((res << 8) | buf[i]) % mod;
    return res;
}

void dfs(int value, const char* r, int index, int i, int j, char* hash) {
    if (i == j) {
        char buf[11 + 16];
        sprintf(buf, "%010d\n", value);
        memcpy(buf + 11, r, 16);
        SHA1((const unsigned char*)buf, 11 + 16, (unsigned char*)hash);
        return;
    }
    int mid = (i + j) / 2;
    char buf[2*SHA_DIGEST_LENGTH];
    if (index <= mid) {
        read_hash(buf + SHA_DIGEST_LENGTH);
        dfs(value, r, index, i, mid, buf);
    } else {
        read_hash(buf);
        dfs(value, r, index, mid + 1, j, buf + SHA_DIGEST_LENGTH);
    }
    SHA1((const unsigned char*)buf, 2*SHA_DIGEST_LENGTH, (unsigned char*)hash);
}

int get_reveal(const char* commitment, int index) {
    int value;
    char r[16];

    value = read_int();
    read(r, 16);
    char tree_hash[SHA_DIGEST_LENGTH];
    dfs(value, r, index, 0, num_nodes - 1, tree_hash);
    CHECK(!memcmp(tree_hash, commitment, SHA_DIGEST_LENGTH));
    return value;
}

int main(int argc, const char* const* argv) {
    setbuf(stdin,0);
    setbuf(stdout,0);
    setbuf(stderr,0);

    if (argc != 3) {
        fprintf(stderr, "Usage: %s graph_file rounds\n", argv[0]);
        return EXIT_FAILURE;
    }

    alarm(10);

    const char* graph_file = argv[1];
    int rounds = atoi(argv[2]);
    printf("Expecting a proof with %d rounds\n", rounds);

    read_graph(graph_file);
    CHECK(SHA1_Init(&ctx));

    int actual_rounds = read_int();
    CHECK(actual_rounds == rounds);

    char* commitments = calloc(rounds, SHA_DIGEST_LENGTH);
    CHECK(commitments);
    for (int i = 0; i < rounds; ++i) {
        read_hash(commitments + i * SHA_DIGEST_LENGTH);
    }

    for (int i = 0; i < rounds; ++i) {
        struct Edge* challenge = edges + randomc(num_edges);
        int cx = get_reveal(commitments + i*SHA_DIGEST_LENGTH, challenge->x - 1);
        int cy = get_reveal(commitments + i*SHA_DIGEST_LENGTH, challenge->y - 1);
        CHECK(cx == 0 || cx == 1 || cx == 2);
        CHECK(cy == 0 || cy == 1 || cy == 2);
        CHECK(cx != cy);
    }

    FILE* f = fopen("flag.txt", "r");
    CHECK(f);
    char buf[101]={0};
    fread(buf, 1, 100, f);
    printf("Good job. Here you go: %s\n", buf);
}
