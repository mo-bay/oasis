#ifndef BITCOIN_CHAINPARAMSSEEDS_H
#define BITCOIN_CHAINPARAMSSEEDS_H
/**
 * List of fixed seed nodes for the bitcoin network
 * AUTOGENERATED by contrib/seeds/generate-seeds.py
 *
 * Each line contains a 16-byte IPv6 address and a port.
 * IPv4 as well as onion addresses are wrapped inside a IPv6 address accordingly.
 */
static SeedSpec6 pnSeed6_main[] = {
    	{{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x12,0xbc,0x2b,0xeb}, 2358},
        {{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x23,0xb1,0xa9,0xf0}, 2358},
        {{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x23,0xb2,0x2b,0xd5}, 2358},
        {{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xc7,0xc0,0x15,0x50}, 2358},
        {{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xc7,0xbc,0xcb,0xa3}, 2358},
        {{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xc7,0xc0,0x15,0x08}, 2358},
        {{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xa2,0xd5,0xf9,0x95}, 2358},
        {{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xa2,0xd5,0xf9,0xd4}, 2358}
};

static SeedSpec6 pnSeed6_test[] = {
		{{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x12,0xbc,0x2b,0xeb}, 6600}

};
#endif // BITCOIN_CHAINPARAMSSEEDS_H