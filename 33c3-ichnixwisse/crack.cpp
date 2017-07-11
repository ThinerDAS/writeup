#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <set>
#include <time.h>
#include <string>
#include <iostream>
#include <openssl/sha.h>

#define CHECK(x) do { \
    if (!(x)) { printf("Big nope at line %d\n", __LINE__); abort(); } }while(0)

#define eprintf(format, ...) fprintf(stderr, "[%s:%d] [%s] " format, __FILE__, __LINE__, __PRETTY_FUNCTION__, ##__VA_ARGS__);fflush(stderr);
struct Edge
{
    int x, y;
}* edges;
int num_nodes, num_edges;

bool fails[5000];

SHA_CTX ctx;

const char* representation[9] =
{
    "0000000000\n",
    "4294967296\n",
    "8589934592\n",

    "0000000001\n",
    "4294967297\n",
    "8589934593\n",

    "0000000002\n",
    "4294967298\n",
    "8589934594\n",
};

std::set<int> prohibit_set[100];

void hexdump ( char* start_addr, char* end_addr )
{
    for ( char* cur_addr = start_addr; cur_addr != end_addr; cur_addr++ )
    {
        printf ( "%02x ", ( *cur_addr ) & 0xff );
    }
    printf ( "\n" );
    for ( char* cur_addr = start_addr; cur_addr != end_addr; cur_addr++ )
    {
        printf ( "%c", *cur_addr );
    }
    printf ( "\n" );
}

void read_graph ( const char* graph_file )
{
    FILE* f = fopen ( graph_file, "r" );
    CHECK ( f );
    CHECK ( 2 == fscanf ( f, "p edge %d %d\n", &num_nodes, &num_edges ) );
    edges = ( struct Edge* ) calloc ( num_edges, sizeof * edges );
    for ( int i = 0; i < num_edges; ++i )
    {
        CHECK ( 2 == fscanf ( f, "e %d %d\n", &edges[i].x, &edges[i].y ) );
        edges[i].x--;
        edges[i].y--;
    }
}

std::string update_entropy ( const char* buf, int cnt )
{
    SHA1_Update ( &ctx, buf, cnt );
    return std::string ( buf, cnt );
}

void clear_entropy()
{
    CHECK ( SHA1_Init ( &ctx ) );
}

void read ( char* buf, int cnt )
{
    CHECK ( ( size_t ) cnt == fread ( buf, 1, cnt, stdin ) );
    update_entropy ( buf, cnt );
}

void read_hash ( char* buf )
{
    read ( buf, SHA_DIGEST_LENGTH );
}

int read_int()
{
    char buf[11];
    read ( buf, 11 );
    CHECK ( buf[10] == '\n' );
    for ( int i = 0; i < 10; ++i )
    {
        CHECK ( isdigit ( buf[i] ) );
    }
    int res;
    sscanf ( buf, "%d", &res );
    return res;
}

int random ( int mod )
{
    SHA_CTX ctx2 = ctx;
    unsigned char buf[SHA_DIGEST_LENGTH];
    SHA1_Final ( buf, &ctx2 );
    int res = 0;
    for ( int i = 0; i < SHA_DIGEST_LENGTH; ++i )
    {
        res = ( ( res << 8 ) | buf[i] ) % mod;
    }
    return res;
}

void dfs ( int value, const char* r, int index, int i, int j, char* hash )
{
    if ( i == j )
    {
        char buf[11 + 16];
        sprintf ( buf, "%010d\n", value );
        memcpy ( buf + 11, r, 16 );
        SHA1 ( ( const unsigned char* ) buf, 11 + 16, ( unsigned char* ) hash );
        return;
    }
    int mid = ( i + j ) / 2;
    char buf[2 * SHA_DIGEST_LENGTH];
    if ( index <= mid )
    {
        read_hash ( buf + SHA_DIGEST_LENGTH );
        dfs ( value, r, index, i, mid, buf );
    }
    else
    {
        read_hash ( buf );
        dfs ( value, r, index, mid + 1, j, buf + SHA_DIGEST_LENGTH );
    }
    SHA1 ( ( const unsigned char* ) buf, 2 * SHA_DIGEST_LENGTH, ( unsigned char* ) hash );
}

int get_reveal ( const char* commitment, int index )
{
    int value;
    char r[16];
    value = read_int();
    read ( r, 16 );
    char tree_hash[SHA_DIGEST_LENGTH];
    dfs ( value, r, index, 0, num_nodes - 1, tree_hash );
    hexdump ( tree_hash, tree_hash + SHA_DIGEST_LENGTH );
    CHECK ( !memcmp ( tree_hash, commitment, SHA_DIGEST_LENGTH ) );
    return value;
}
const char graph_file[] = "graph.txt";

int getmincount ( int* arr, int cnt )
{
    int res = 0, minv = arr[0];
    for ( int i = 1; i < cnt; i++ )
    {
        if ( arr[i] < minv )
        {
            res = i;
            minv = arr[i];
        }
    }
    return res;
}

void getcolors ( int* colors )
{
    //read_graph ( graph_file );
    //int colors[100];
    for ( int i = 0; i < 100; i++ )
    {
        colors[i] = ( ( rand() % 3 ) + 6 ) % 3;
    }
    int T = 10;
    for ( int t = 0; t < T; t++ )
    {
        for ( int i = 0; i < 100; i++ )
        {
            int count[3] = {};
            for ( int adj_node : prohibit_set[i] )
            {
                count[colors[adj_node]]++;
            }
            colors[i] = getmincount ( count, 3 );
        }
    }
    for ( int i = 0; i < num_edges; i++ )
    {
        int x = edges[i].x, y = edges[i].y;
        fails[i] = ( colors[x] == colors[y] );
    }
    /*
    for ( int i = 0; i < 100; i++ )
    {
        printf ( "%d\t%d\n", i, colors[i] );
    }
    printf ( "Fails: %d\n", fails );
    */
    //return 0;
}

void init_graph()
{
    read_graph ( graph_file );
    for ( int i = 0; i < num_edges; i++ )
    {
        int x = edges[i].x, y = edges[i].y;
        prohibit_set[x].insert ( y );
        prohibit_set[y].insert ( x );
    }
}

struct btree_node
{
    char hash[SHA_DIGEST_LENGTH];
    struct btree_node* left;
    struct btree_node* right;
    btree_node() : hash{}, left ( NULL ), right ( NULL ) {}
};

typedef struct btree_node Bnode;

void walktree ( char singlehash[][SHA_DIGEST_LENGTH], int i, int j, Bnode* node )
{
    if ( i == j )
    {
        memcpy ( node->hash, singlehash[i], SHA_DIGEST_LENGTH );
        return;
    }
    int mid = ( i + j ) / 2;
    char buf[2 * SHA_DIGEST_LENGTH];
    node->left = new Bnode();
    walktree ( singlehash, i, mid, node->left );
    node->right = new Bnode();
    walktree ( singlehash, mid + 1, j, node->right );
    memcpy ( buf, node->left->hash, SHA_DIGEST_LENGTH );
    memcpy ( buf + SHA_DIGEST_LENGTH, node->right->hash, SHA_DIGEST_LENGTH );
    SHA1 ( ( const unsigned char* ) buf, 2 * SHA_DIGEST_LENGTH, ( unsigned char* ) node->hash );
}

std::string emu_dfs ( Bnode* root, int index, int i, int j )
{
    // return payload, change the laypot of entropy
    if ( i == j )
    {
        return std::string();
    }
    std::string pl;
    int mid = ( i + j ) / 2;
    if ( index <= mid )
    {
        pl = update_entropy ( root->right->hash, SHA_DIGEST_LENGTH );
        pl += emu_dfs ( root->left, index, i, mid );
    }
    else
    {
        pl = update_entropy ( root->left->hash, SHA_DIGEST_LENGTH );
        pl += emu_dfs ( root->right, index, mid + 1, j );
    }
    return pl;
}

std::string dfsSearch ( Bnode* root, const char* salt, const int colors[100], int edge_id, int repr1, int repr2, int ns )
{
    //eprintf ( "called once!\n" );
    std::string prefix, suffix;
    // walk through the process
    int x = edges[edge_id].x, y = edges[edge_id].y;
    const char* reprx = representation[colors[x] * 3 + repr1];
    const char* repry = representation[colors[y] * 3 + repr2];
    prefix += update_entropy ( reprx, 11 );
    prefix += update_entropy ( salt, 16 );
    prefix += emu_dfs ( root, x, 0, 99 );
    prefix += update_entropy ( repry, 11 );
    prefix += update_entropy ( salt, 16 );
    prefix += emu_dfs ( root, y, 0, 99 );
    // and then record the current status
    if ( ns == 1 )
    {
        goto SUCCEED;
    }
    {
        int new_edge_id = random ( num_edges );
        if ( fails[new_edge_id] )
        {
            return std::string();
        }
        SHA_CTX ctx2 = ctx;
        for ( int i = 0; i < 3; i++ )
        {
            for ( int j = 0; j < 3; j++ )
            {
                //eprintf ( "recasted once on loop %d!\n", ns );
                ctx = ctx2;
                suffix = dfsSearch ( root, salt, colors, new_edge_id, i, j, ns - 1 );
                if ( !suffix.empty() )
                {
                    goto SUCCEED;
                }
            }
        }
        return std::string();
    }
SUCCEED:
    return prefix + suffix;
}

std::string waves ( Bnode* root, char* salt, const int colors[100] )
{
    int edge_id = random ( num_edges );
    if ( fails[edge_id] )
    {
        return std::string();
    }
    std::string ret;
    SHA_CTX ctx2 = ctx;
    for ( int i = 0; i < 3; i++ )
    {
        for ( int j = 0; j < 3; j++ )
        {
            ctx = ctx2;
            ret = dfsSearch ( root, salt, colors, edge_id, i, j, 300 );
            if ( !ret.empty() )
            {
                goto SUCCEED;
            }
            //eprintf ( "recasted once!\n" );
        }
    }
    return std::string();
SUCCEED:
    return ret;
}

std::string genpl ( int colors[100], char salt[16] )
{
    std::string ret;
    clear_entropy();
    ret += update_entropy ( "0000000300\n", 11 );
    char singlehash[100][SHA_DIGEST_LENGTH];
    char buf[11 + 16] = {};
    for ( int i = 0; i < 100; i++ )
    {
        sprintf ( buf, "%010d\n", colors[i] );
        memcpy ( buf + 11, salt, 16 );
        SHA1 ( ( const unsigned char* ) buf, 11 + 16, ( unsigned char* ) singlehash[i] );
    }
    //char nullsalt[SHA_DIGEST_LENGTH] = {};
    Bnode* root = new Bnode();
    walktree ( singlehash, 0, 99, root );
    for ( int i = 0; i < 300; i++ )
    {
        ret += update_entropy ( root->hash, SHA_DIGEST_LENGTH );
    }
    std::string payload_suf = waves ( root, salt, colors );
    if ( !payload_suf.empty() )
    {
        return ret + payload_suf;
    }
    else
    {
        return std::string();
    }
}

int main ()
{
    srand ( time ( 0 ) );
    CHECK ( SHA1_Init ( &ctx ) );
    init_graph();
    int colors[100];
    std::string payload_str;
    while ( payload_str.empty() )
    {
        getcolors ( colors );
        char salt[16] = {};
        for ( int i = 0; i < 256; i++ )
        {
            salt[1] = i;
            payload_str = genpl ( colors, salt );
            if ( !payload_str.empty() )
            {
                break;
            }
        }
    }
    std::cout << payload_str;
    fprintf ( stderr, "Completed generating payload.\n" );
}

/*
int main()
{
    CHECK ( SHA1_Init ( &ctx ) );
    puts ( "Ready" );
    for ( int i = 0; i < 10; i++ )
    {
        printf ( "readint=%lld\n", read_int() );
    }
    SHA_CTX ctx2 = ctx;
    unsigned char buf[SHA_DIGEST_LENGTH];
    SHA1_Final ( buf, &ctx2 );
    hexdump ( ( char* ) buf, ( char* ) buf + SHA_DIGEST_LENGTH );
    return 0;
}*/
