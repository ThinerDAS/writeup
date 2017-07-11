#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <queue>
#include <stack>
#include <bitset>
#include <assert.h>

#include <string.h>

// flag starts with flag{IDE

struct gate
{
    int type;
    int in1;
    int in2;
    int in3;
    int out;
};

std::vector<gate> gates;
std::vector<gate> sorted_gates;
int ids = 0;
int id[0x42000];
int indeg[0x42000];
// can be used as back searching
std::vector<int> depended_nodes[0x42000];

int and_op ( int a1, int a2, int )
{
    return a1 & a2;
}

int or_op ( int a1, int a2, int )
{
    return a1 | a2;
}

int xor_op ( int a1, int a2, int )
{
    return a1 ^ a2;
}

int mux_op ( int a1, int a2, int a3 )
{
    return a1 ? a2 : a3;
}

typedef int ( *atomic_op ) ( int, int, int );

atomic_op op[10] = {0, and_op, or_op, xor_op, mux_op};

long readq ( FILE* f )
{
    long l;
    fread ( &l, sizeof ( l ), 1, f );
    return l;
}

gate read_gate ( FILE* f )
{
    gate ret;
    ret.type = readq ( f );
    ret.in1 = readq ( f );
    ret.in2 = readq ( f );
    ret.in3 = readq ( f );
    ret.out = readq ( f );
    return ret;
}

void ppg ( gate g )
{
    //printf ( "type=%d\nin=%d,%d,%d\nout=%d\n\n", g.type, g.in1, g.in2, g.in3, g.out );
    switch ( g.type )
    {
        case 1:
            //AND
            printf ( "[%5x]=[%5x]&[%5x]\n", id[g.out], id[g.in1], id[g.in2] );
            break;
        case 2:
            //OR
            printf ( "[%5x]=[%5x]|[%5x]\n", id[g.out], id[g.in1], id[g.in2] );
            break;
        case 3:
            //XOR
            printf ( "[%5x]=[%5x]^[%5x]\n", id[g.out], id[g.in1], id[g.in2] );
            break;
        case 4:
            //MUX
            printf ( "[%5x]=[%5x]?[%5x]:[%5x]\n", id[g.out], id[g.in1], id[g.in2], id[g.in3] );
            break;
        default:
            printf ( "gtype=%d", g.type );
            assert ( !"Unexpected gate!!!" );
    }
}

void resort()
{
    // resort gates based on its usage
    std::queue<int> nodes;
    for ( int i = 0, s = gates.size(); i < s; i++ )
    {
        assert ( gates[i].type != 0 );
        if ( gates[i].type != -1 && gates[i].type != 0 )
        {
            int ins[3] = {gates[i].in1, gates[i].in2, gates[i].in3};
            assert ( gates[i].out != -1 );
            for ( int j = 0; j < 3; j++ )
            {
                int ii = ins[j];
                if ( ii != -1 )
                {
                    depended_nodes[ii].push_back ( gates[i].out );
                    indeg[gates[i].out]++;
                }
            }
        }
    }
    nodes.push ( 0 );
    nodes.push ( 1 );
    for ( int i = 2, s = gates.size(); i < s; i++ )
    {
        if ( indeg[i] == 0 )
        {
            nodes.push ( i );
        }
    }
    while ( !nodes.empty() )
    {
        int cur_node = nodes.front();
        //printf ( "cur_node=%d\n", cur_node );
        nodes.pop();
        for ( int i : depended_nodes[cur_node] )
        {
            indeg[i]--;
            //printf ( "i=%d,ind=%d\n", i, indeg[i] );
            if ( indeg[i] == 0 )
            {
                nodes.push ( i );
                sorted_gates.push_back ( gates[i] );
                //ppg ( gates[i] );
            }
        }
    }
}

void setbs ( std::bitset<0x42000>& bs, const char* buf, int* ports )
{
    //bs.reset();
    bs.reset ( 0 );
    bs.set ( 1 );
    for ( int i = 0; i < 8; i++ )
    {
        int c = ( unsigned char ) ( buf[i] );
        for ( int j = 0; j < 8; j++ )
        {
            if ( ( c >> j ) & 1 )
            {
                bs.set ( ports[i * 8 + j] );
            }
            else
            {
                bs.reset ( ports[i * 8 + j] );
            }
        }
    }
}

void getbs ( std::bitset<0x42000>& bs, char* buf, int* ports )
{
    for ( int i = 0; i < 8; i++ )
    {
        int c = 0;
        for ( int j = 0; j < 8; j++ )
        {
            if ( bs.test ( ports[i * 8 + j] ) )
            {
                c |= 1 << j;
            }
        }
        buf[i] = c;
    }
}

void hexdump ( char* buf, int len )
{
    for ( int i = 0; i < len; i++ )
    {
        printf ( "%02x", buf[i] & 0xff );
    }
    putchar ( 10 );
}

void calc ( std::bitset<0x42000>& bs )
{
    for ( gate g : sorted_gates )
    {
        int a1 = 0, a2 = 0, a3 = 0;
        if ( g.in1 != -1 )
        {
            a1 = bs.test ( g.in1 );
        }
        if ( g.in2 != -1 )
        {
            a2 = bs.test ( g.in2 );
        }
        if ( g.in3 != -1 )
        {
            a3 = bs.test ( g.in3 );
        }
        int out = 0;
        switch ( g.type )
        {
            case 1:
                //AND
                out = ( a1 & a2 );
                break;
            case 2:
                //OR
                out = ( a1 | a2 );
                break;
            case 3:
                //XOR
                out = ( a1 ^ a2 );
                break;
            case 4:
                //MUX
                out = a1 ? a2 : a3;
                break;
            default:
                printf ( "gtype=%d", g.type );
                assert ( !"Unexpected gate!!!" );
        }
        if ( out )
        {
            bs.set ( g.out );
        }
        else
        {
            bs.reset ( g.out );
        }
    }
}

void idea ( std::bitset<0x42000>& bs, const char* in, char* out, int* in_ports, int* out_ports )
{
    setbs ( bs, in, in_ports );
    calc ( bs );
    getbs ( bs, out, out_ports );
}

int translate ( int type, int p1, int p2, int p3, int* buf )
{
    int ps[] = {p1, p2, p3};
    int vs[3];
    int vals[3];
    for ( int i = 0; i < 3; i++ )
    {
        if ( ps[i] == -1 )
        {
            vals[i] = -1;
        }
        else
        {
            vs[i] = id[ps[i]];
            if ( vs[i] == 0xfa15e )
            {
                vals[i] = 0;
            }
            else if ( vs[i] == 0x720ee )
            {
                vals[i] = 1;
            }
            else
            {
                vals[i] = buf[vs[i]];
            }
        }
    }
    return op[type] ( vals[0], vals[1], vals[2] );
}

struct command
{
    int op;
    int arg;
};

int main ( int argc, char* argv[] )
{
    int i1 = 16, i2 = 32;
    if ( argc >= 3 )
    {
        i1 = atoi ( argv[1] );
        i2 = atoi ( argv[2] );
    }
    FILE* f1 = fopen ( "cp", "rb" );
    FILE* f2 = fopen ( "ip", "rb" );
    FILE* f3 = fopen ( "op", "rb" );
    long node_cnt = readq ( f1 );
    long gate_cnt = readq ( f1 );
    long in_cnt = readq ( f2 );
    long out_cnt = readq ( f3 );
    int in_ports[64];
    int out_ports[64];
    for ( int i = 0; i < in_cnt; i++ )
    {
        in_ports[i] = readq ( f2 );
    }
    for ( int i = 0; i < out_cnt; i++ )
    {
        out_ports[i] = readq ( f3 );
    }
    gate inv;
    inv.type = inv.in1 = inv.in2 = inv.in3 = inv.out = -1;
    gates = std::vector<gate> ( node_cnt, inv );
    for ( int i = 0; i < gate_cnt; i++ )
    {
        gate g = read_gate ( f1 );
        gates[g.out] = g;
    }
    resort();
    printf ( "id in      out\n" );
    for ( int i = 0; i < 64; i++ )
    {
        printf ( "%2d %7d %7d\n", i, in_ports[i], out_ports[i] );
    }
    printf ( "prelogue END\n" );
    const int journey_start = 'o';
    const int go_up_assert = 'p';
    const int go_down_assert = 'q';
    const int go_side_assert = 'r';
    const int output = 's';
    const int go_back = 't';
    const int journet_end = 'u';
    const int type_mask = 0xff;
    const int const_pos = 8;
    //const int been_pos=10;
    const int ynn_mask = 3;
    const int ynn_neutral = 0;
    const int ynn_pro = 1;
    const int ynn_con = 2;
    while ( 1 )
    {
        //read in a vector of command
        std::vector<command> commands;
        char buf[16];
        while ( 1 )
        {
            scanf ( "%15s", buf );
            if ( buf[0] == journet_end )
            {
                break;
            }
            else if ( buf[0] >= journey_start && buf[0] < journet_end )
            {
                command cm;
                cm.op = buf[0];
                int val = scanf ( "%i", &cm.arg );
                assert ( val == 1 );
                commands.push_back ( cm );
            }
        }
        // do as what commands speak
        // store a stack
        // and a current_pointer
        assert ( commands[0].op == journey_start );
        struct stack_frame_t
        {
            std::vector<int> node;
            int last_stackframe_id;
        };
        std::vector<stack_frame_t> call_stack;
        stack_frame_t initial_stack_element;
        int init_node = commands[0].arg;
        initial_stack_element.node.push_back ( init_node );
        initial_stack_element.last_stackframe_id = -1;
        call_stack.push_back ( initial_stack_element );
        //std::vector<int> route_stack;
        //route_stack.push_back ( init_node );
        while ( !call_stack.empty() && call_stack.size() != commands.size() )
        {
            // find next element
            auto& stack_top = call_stack.back();
            if ( stack_top.node.empty() )
            {
                // pop and return
                call_stack.pop_back();
                if ( call_stack.empty() )
                {
                    break;
                }
                call_stack.back().node.pop_back();
                //route_stack.pop_back();
                continue;
            }
            int this_node = stack_top.node.back();
            //route_stack.push_back ( this_node );
            command cm = commands[call_stack.size()];
            switch ( cm.op )
            {
                case journey_start:
                    assert ( !"cannot start twice" );
                    break;
                case go_side_assert:
                {
                    stack_frame_t stack_frame;
                    stack_frame.last_stackframe_id = call_stack.size() - 1;
                    for ( int i : depended_nodes[this_node] )
                    {
                        // satisfying some criteria, will be push into the stack frame that will be push into stack later
                        int do_const = ( ( cm.arg >> const_pos ) &ynn_mask );
                        //int do_been=((cm.arg>>been_pos)&ynn_mask );
                        int type = ( cm.arg & type_mask );
                        bool accept = true;
                        if ( type && gates[i].type != type )
                        {
                            accept = false;
                        }
                        if ( accept )
                        {
                            //iterate all its input and mask out itself
                            //and based on const criteria mask out some
                            int cand[3] = {gates[i].in1, gates[i].in2, gates[i].in3};
                            for ( int j = 0; j < 3; j++ )
                            {
                                if ( cand[j] == -1 )
                                {
                                    continue;
                                }
                                if ( cand[j] == this_node )
                                {
                                    continue;
                                }
                                if ( do_const )
                                {
                                    if ( ( do_const == ynn_pro ) != ( cand[i] <= 1 ) )
                                    {
                                        continue;
                                    }
                                }
                                stack_frame.node.push_back ( cand[j] );
                            }
                        }
                    }
                    call_stack.push_back ( stack_frame );
                }
                break;
                case go_up_assert:
                {
                    stack_frame_t stack_frame;
                    stack_frame.last_stackframe_id = call_stack.size() - 1;
                    {
                        // satisfying some criteria, will be push into the stack frame that will be push into stack later
                        int do_const = ( ( cm.arg >> const_pos ) &ynn_mask );
                        //int do_been=((cm.arg>>been_pos)&ynn_mask );
                        int type = ( cm.arg & type_mask );
                        bool accept = true;
                        if ( type && gates[this_node].type != type )
                        {
                            accept = false;
                        }
                        if ( accept )
                        {
                            //iterate all its input and mask out itself
                            //and based on const criteria mask out some
                            int cand[3] = {gates[this_node].in1, gates[this_node].in2, gates[this_node].in3};
                            for ( int i = 0; i < 3; i++ )
                            {
                                if ( cand[i] == -1 )
                                {
                                    continue;
                                }
                                if ( cand[i] == this_node )
                                {
                                    continue;
                                }
                                if ( do_const )
                                {
                                    if ( ( do_const == ynn_pro ) != ( cand[i] <= 1 ) )
                                    {
                                        continue;
                                    }
                                }
                                stack_frame.node.push_back ( cand[i] );
                            }
                        }
                    }
                    call_stack.push_back ( stack_frame );
                }
                break;
                case go_down_assert:
                {
                    stack_frame_t stack_frame;
                    stack_frame.last_stackframe_id = call_stack.size() - 1;
                    for ( int i : depended_nodes[this_node] )
                    {
                        // satisfying some criteria, will be push into the stack frame that will be push into stack later
                        int do_const = ( ( cm.arg >> const_pos ) &ynn_mask );
                        //int do_been=((cm.arg>>been_pos)&ynn_mask );
                        int type = ( cm.arg & type_mask );
                        bool accept = true;
                        if ( type && gates[i].type != type )
                        {
                            accept = false;
                        }
                        // going down will never run into a const
                        assert ( do_const != ynn_pro );
                        if ( accept )
                        {
                            stack_frame.node.push_back ( i );
                        }
                    }
                    call_stack.push_back ( stack_frame );
                }
                break;
                case output:
                    // do nothing in first stage
                {
                    stack_frame_t stack_frame;
                    stack_frame.last_stackframe_id = call_stack.back().last_stackframe_id;
                    stack_frame.node.push_back ( this_node );
                    call_stack.push_back ( stack_frame );
                }
                break;
                case go_back:
                {
                    // first find out what the last node is
                    stack_frame_t stack_frame;
                    int last_last = call_stack.back().last_stackframe_id;
                    assert ( last_last >= 0 );
                    stack_frame.last_stackframe_id = call_stack[last_last].last_stackframe_id;
                    stack_frame.node.push_back ( call_stack[last_last].node.back() );
                    call_stack.push_back ( stack_frame );
                    /*
                    assert(route_stack.size()>=2)
                    int last_node=route_stack[route_stack.size()-2];
                    std::vector<int> stack_frame;
                    stack_frame.push_back ( last_node );
                    call_stack.push_back ( stack_frame );
                    */
                }
                    //assert ( !"unimplemented" );
                break;
                default:
                    printf ( "unrecognized cmd: %d %d", cm.op, cm.arg );
                    assert ( !"wtf the command!?" );
                    break;
            }
        }
        if ( call_stack.size() == commands.size() )
        {
            // output
            for ( int i = 0, s = commands.size(); i < s; i++ )
            {
                command cm = commands[i];
                if ( cm.op == output )
                {
                    printf ( "%d\n", call_stack[i].node.back() );
                }
            }
        }
        else
        {
            printf ( "-1\n" );
        }
        printf ( "END at node %5x END\n",call_stack.back().node.back() );
        // read from journey start to journey end
    }
    //printf("gates unsorted size=%d\n",gates.size());
    //printf("gates sorted size=%d\n",sorted_gates.size());
    //printf("\n\n");
    //ppg(gates[84553]);
    std::bitset<0x42000> bs;
    printf ( "all prepared\n" );
    // forward-trace
    // back trace not now
    int sub_in_ports[16];
    int sub_out_ports[16];
    int possible_add_out[16] = {0x22, 0x28, 0x2c, 0x32,
                                0x37, 0x3b, 0x41, 0x46,
                                0x48, 0x4c, 0x4f, 0x52,
                                0x55, 0x57, 0x5b, 0x5e
                               };
    int index[16] = {8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7};
    for ( int i = i1, idest = i2; i < idest; i++ )
    {
        //id[in_ports[i / 16 * 16 + i % 8 + ( 1 - ( i / 8 ) % 2 ) * 8]] = ids++;
        sub_in_ports[i % 16] = in_ports[i / 16 * 16 + i % 8 + ( 1 - ( i / 8 ) % 2 ) * 8];
    }
    for ( int t = 0; t < 8; t++ )
    {
        // find 8 k2s
        // first recognize the add part
        printf ( "turn %d\n", t );
        memset ( id, 0, sizeof ( id ) );
        {
            bs.reset();
            bs.set ( 0 );
            bs.set ( 1 );
            ids = 0;
            int add_output_port[128];
            id[0] = 0xfa15e;
            id[1] = 0x720ee;
            for ( int i = 0; i < 16; i++ )
            {
                id[sub_in_ports[i]] = ids++;
            }
            ids = 0x100000;
            for ( gate g : sorted_gates )
            {
                if ( bs.test ( g.out ) )
                {
                    continue;
                }
                if ( g.in1 != -1 && !bs.test ( g.in1 ) )
                {
                    continue;
                }
                if ( g.in2 != -1 && !bs.test ( g.in2 ) )
                {
                    continue;
                }
                if ( g.in3 != -1 && !bs.test ( g.in3 ) )
                {
                    continue;
                }
                // good
                bs.set ( g.out );
                id[g.out] = ids++;
                //ppg ( gates[g.out] );
            }
            ids = 16;
            for ( int i = 0, idest = 16; i < idest; i++ )
            {
                printf ( "=== insert %d ===\n", i );
                int port = sub_in_ports[index[i]];
                printf ( "port=%x\n", port );
                bs.set ( port );
                int ds[4] = {};
                for ( gate g : sorted_gates )
                {
                    if ( bs.test ( g.out ) )
                    {
                        ds[0]++;
                        continue;
                    }
                    if ( g.in1 != -1 && !bs.test ( g.in1 ) )
                    {
                        ds[1]++;
                        continue;
                    }
                    if ( g.in2 != -1 && !bs.test ( g.in2 ) )
                    {
                        ds[2]++;
                        continue;
                    }
                    if ( g.in3 != -1 && !bs.test ( g.in3 ) )
                    {
                        ds[3]++;
                        continue;
                    }
                    // good
                    bs.set ( g.out );
                    add_output_port[ids] = g.out;
                    id[g.out] = ids++;
                    ppg ( gates[g.out] );
                }
                for ( int j = 0; j < 4; j++ )
                {
                    printf ( "die time from %d: %d\n", j, ds[j] );
                }
            }
            int minids = 16;
            int maxids = ids;
            for ( int i = 0; i < 16; i++ )
            {
                sub_out_ports[i] = add_output_port[possible_add_out[i]];
            }
            // test to find out the add operand
            int calc_result_raw[256];
            for ( int j = 0; j < 16; j++ )
            {
                calc_result_raw[j] = 0;
            }
            for ( int j = minids; j < maxids; j++ )
            {
                int addr = add_output_port[j];
                gate g = gates[addr];
                calc_result_raw[j] = translate ( g.type, g.in1, g.in2, g.in3, calc_result_raw );
            }
            int operand = 0;
            for ( int i = 0; i < 16; i++ )
            {
                operand |= calc_result_raw[possible_add_out[i]] << i;
            }
            printf ( "op: %04x\n", operand );
            // traverse the xor object
            for ( gate g : sorted_gates )
            {
                if ( bs.test ( g.out ) )
                {
                    continue;
                }
                if ( ! ( ( g.in1 != -1 && id[g.in1] < maxids && id[g.in1] > minids ) || ( g.in2 != -1 && id[g.in2] < maxids && id[g.in2] > minids ) || ( g.in3 != -1 && id[g.in3] < maxids && id[g.in3] > minids ) ) )
                {
                    if ( g.in1 != -1 && !bs.test ( g.in1 ) )
                    {
                        continue;
                    }
                    if ( g.in2 != -1 && !bs.test ( g.in2 ) )
                    {
                        continue;
                    }
                    if ( g.in3 != -1 && !bs.test ( g.in3 ) )
                    {
                        continue;
                    }
                }
                // good
                assert ( g.type == 3 );
                int good_pa = -1;
                int good_id = -1;
                if ( id[g.in1] < maxids && id[g.in1] > minids )
                {
                    good_pa = g.in1;
                    good_id = id[g.in1];
                }
                else if ( id[g.in2] < maxids && id[g.in2] > minids )
                {
                    good_pa = g.in2;
                    good_id = id[g.in2];
                }
                assert ( good_id != -1 );
                int good_pos = -1;
                for ( int i = 0; i < 16; i++ )
                {
                    if ( possible_add_out[i] == good_id )
                    {
                        good_pos = i;
                    }
                }
                assert ( good_pos != -1 );
                ppg ( gates[g.out] );
                printf ( "good_pos=%x, g.out=%x\n", good_pos, g.out );
                sub_in_ports[good_pos] = g.out;
                /*
                id[g.out] = ids++;
                if ( g.in1 != -1 && !bs.test ( g.in1 ) )
                {
                    id[g.in1] = 0xe00000 + ( g.in1 );
                }
                if ( g.in2 != -1 && !bs.test ( g.in2 ) )
                {
                    id[g.in2] = 0xe00000 + ( g.in2 );
                }
                if ( g.in3 != -1 && !bs.test ( g.in3 ) )
                {
                    id[g.in3] = 0xe00000 + ( g.in3 );
                }
                */
            }
        }
    }
    return 0;
    /*
    int minids = i2 - i1;
    int maxids = ids;
    bool impossible[16][16] = {};
    int calc_result_raw[256];
    int addval = 0xb2fd;//64946;
    for ( int t = 0; t < 1000; t++ )
    {
        int rand_val = rand() & 0xffff;
        int result = ( rand_val + addval ) & 0xffff;
        for ( int j = 0; j < 16; j++ )
        {
            calc_result_raw[j] = ( rand_val >> j ) & 1;
        }
        for ( int j = minids; j < maxids; j++ )
        {
            int addr = add_output_port[j];
            gate g = gates[addr];
            calc_result_raw[j] = translate ( g.type, g.in1, g.in2, g.in3, calc_result_raw );
        }
        for ( int i = 0; i < 16; i++ )
            for ( int j = 0; j < 16; j++ )
            {
                if ( calc_result_raw[possible_add_out[i]] != ( 1 & ( result >> j ) ) )
                {
                    if ( i == 0 && j == 0 )
                    {
                        printf ( "randval=%d\n", rand_val );
                    }
                    impossible[j][i] = true;
                }
            }
    }
    for ( int i = 0; i < 16; i++ )
    {
        printf ( "\nCandidate for bit %2d:", i );
        for ( int j = 0; j < 16; j++ )
        {
            if ( !impossible[i][j] )
            {
                printf ( "%02x(%02x)  ", possible_add_out[j], j );
            }
        }
    }
    */
    /*
    for ( gate g : sorted_gates )
    {
        if ( bs.test ( g.out ) )
        {
            continue;
        }
        if ( ! ( ( id[g.in1] < maxids && id[g.in1] > minids ) || ( id[g.in2] < maxids && id[g.in2] > minids ) || ( id[g.in3] < maxids && id[g.in3] > minids ) ) )
        {
            if ( g.in1 != -1 && !bs.test ( g.in1 ) )
            {
                continue;
            }
            if ( g.in2 != -1 && !bs.test ( g.in2 ) )
            {
                continue;
            }
            if ( g.in3 != -1 && !bs.test ( g.in3 ) )
            {
                continue;
            }
        }
        // good
        id[g.out] = ids++;
        if ( g.in1 != -1 && !bs.test ( g.in1 ) )
        {
            id[g.in1] = 0xe00000 + ( g.in1 );
        }
        if ( g.in2 != -1 && !bs.test ( g.in2 ) )
        {
            id[g.in2] = 0xe00000 + ( g.in2 );
        }
        if ( g.in3 != -1 && !bs.test ( g.in3 ) )
        {
            id[g.in3] = 0xe00000 + ( g.in3 );
        }
        ppg ( gates[g.out] );
    }
    */
    /*
    for ( int i = i1; i < i2; i++ )
    {
        in_buf[5] = i;
        printf ( "i=%d\n", i );
        for ( int j = 32; j < 127; j++ )
        {
            in_buf[6] = j;
            for ( int k = 32; k < 127; k++ )
            {
                in_buf[7] = k;
                idea ( bs, in_buf, buf, in_ports, out_ports );
                if ( !memcmp ( buf, "\x96\x6e\xc0\x8f\x41\xfe\x10\x0a", 8 ) )
                {
                    puts ( "Flag:" );
                    puts ( in_buf );
                }
            }
        }
    }*/
    return 0;
}
