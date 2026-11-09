#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* Feature gate: 60 policy bits packed into a hex token. */
static int flag_bit(const char *flags, int idx) {
    int pos = idx / 4;
    int nib;
    char c;
    if (flags == NULL || pos >= (int)strlen(flags)) {
        return 0;
    }
    c = flags[pos];
    if (c >= '0' && c <= '9') {
        nib = c - '0';
    } else if (c >= 'a' && c <= 'f') {
        nib = c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        nib = c - 'A' + 10;
    } else {
        return 0;
    }
    return (nib >> (idx % 4)) & 1;
}

static int policy_a(const int *f) {
    return (f[12] || f[9] || !f[3]) && (f[3] || !f[1] || f[6]) && (f[0] || f[10] || !f[14]) &&
           (f[0] || f[7] || !f[14]) && (f[9] || f[12] || f[15]) && (!f[13] || !f[6] || !f[17]) &&
           (f[11] || !f[12] || f[18]) && (!f[15] || !f[7] || !f[1]) && (f[6] || f[19] || !f[3]) &&
           (!f[5] || !f[10] || f[12]) && (!f[2] || f[16] || !f[9]) && (f[1] || !f[8] || f[0]) &&
           (f[14] || f[4] || f[3]) && (f[15] || f[19] || f[8]) && (f[9] || f[15] || f[6]) &&
           (!f[15] || !f[1] || f[12]) && (f[0] || f[1] || !f[13]) && (f[4] || f[13] || f[6]) &&
           (f[17] || !f[13] || !f[6]) && (!f[8] || f[4] || !f[17]) && (!f[0] || !f[11] || f[8]) &&
           (f[10] || !f[9] || !f[17]) && (f[7] || !f[6] || f[1]) && (!f[0] || f[8] || f[6]) &&
           (f[6] || !f[13] || !f[9]) && (!f[17] || !f[14] || f[5]) && (f[14] || f[11] || f[15]) &&
           (f[17] || !f[12] || f[8]) && (f[6] || !f[14] || f[8]) && (!f[17] || !f[7] || f[18]) &&
           (f[13] || !f[6] || f[7]) && (!f[19] || !f[3] || f[1]) && (f[0] || f[10] || !f[5]) &&
           (f[13] || f[8] || !f[2]) && (!f[18] || !f[10] || !f[9]) && (f[17] || !f[18] || !f[4]) &&
           (f[13] || !f[11] || !f[10]) && (f[0] || !f[12] || !f[16]) && (!f[4] || !f[19] || f[1]) &&
           (f[12] || !f[15] || f[4]) && (!f[4] || f[11] || !f[16]) && (!f[8] || f[18] || !f[17]) &&
           (f[8] || !f[6] || f[16]) && (!f[19] || f[14] || f[5]) && (f[14] || !f[5] || !f[12]) &&
           (f[15] || !f[3] || !f[12]) && (!f[6] || f[13] || f[3]) && (f[1] || f[11] || f[3]) &&
           (f[8] || !f[15] || f[12]) && (f[6] || f[3] || !f[8]) && (!f[18] || f[7] || f[15]) &&
           (f[19] || f[9] || f[14]) && (!f[7] || f[2] || !f[15]) && (!f[2] || !f[12] || f[16]) &&
           (f[14] || !f[2] || !f[15]) && (f[17] || !f[5] || !f[8]) && (f[12] || !f[3] || f[11]) &&
           (f[1] || f[14] || f[11]) && (!f[18] || f[10] || f[15]) && (f[10] || f[4] || !f[11]) &&
           (!f[6] || f[15] || f[7]) && (f[7] || f[3] || f[11]) && (f[4] || f[3] || !f[6]) &&
           (f[5] || !f[9] || !f[0]) && (!f[12] || f[8] || !f[11]) && (!f[4] || !f[0] || f[5]) &&
           (f[3] || !f[16] || f[19]) && (f[8] || !f[19] || f[1]) && (!f[4] || f[12] || f[10]) &&
           (!f[9] || !f[2] || !f[17]) && (!f[17] || !f[6] || !f[4]) && (!f[10] || !f[6] || f[11]) &&
           (!f[6] || !f[10] || !f[18]) && (f[6] || f[12] || !f[9]) && (!f[19] || f[0] || !f[9]) &&
           (f[19] || f[6] || !f[10]) && (f[14] || !f[17] || f[8]) && (!f[4] || f[18] || f[14]) &&
           (!f[18] || f[16] || f[11]) && (f[5] || f[3] || f[17]) && (f[8] || f[1] || f[19]) &&
           (!f[11] || f[16] || !f[19]) && (f[12] || f[5] || f[16]) && (!f[13] || !f[1] || f[19]) &&
           (!f[19] || f[3] || !f[16]);
}

static int policy_b(const int *f) {
    return (f[32] || f[34] || f[33]) && (!f[23] || f[39] || f[21]) && (!f[37] || f[38] || f[34]) &&
           (f[26] || !f[20] || f[32]) && (!f[37] || !f[26] || !f[38]) && (f[22] || f[34] || f[20]) &&
           (f[24] || f[34] || f[39]) && (!f[38] || !f[33] || f[35]) && (f[25] || f[34] || !f[31]) &&
           (!f[26] || f[32] || !f[37]) && (f[32] || f[23] || !f[29]) && (f[30] || !f[27] || f[36]) &&
           (!f[39] || f[26] || !f[21]) && (!f[22] || !f[24] || f[32]) && (f[24] || !f[22] || !f[29]) &&
           (!f[37] || !f[30] || !f[22]) && (!f[31] || f[38] || f[29]) && (!f[28] || f[31] || !f[37]) &&
           (f[27] || f[29] || f[32]) && (!f[23] || !f[25] || f[20]) && (f[28] || f[21] || !f[30]) &&
           (!f[22] || f[32] || !f[28]) && (!f[38] || f[26] || !f[34]) && (!f[20] || !f[31] || f[28]) &&
           (f[34] || f[26] || !f[27]) && (f[29] || f[33] || !f[22]) && (f[30] || !f[29] || f[33]) &&
           (!f[33] || f[31] || f[20]) && (!f[30] || !f[23] || f[38]) && (f[29] || f[30] || f[21]) &&
           (!f[36] || !f[34] || f[33]) && (f[20] || f[24] || !f[21]) && (!f[33] || !f[26] || f[35]) &&
           (!f[23] || f[21] || !f[31]) && (!f[28] || f[27] || !f[32]) && (f[35] || !f[25] || !f[32]) &&
           (f[20] || f[35] || !f[26]) && (!f[24] || !f[37] || !f[21]) && (!f[39] || f[34] || f[28]) &&
           (!f[28] || !f[36] || f[25]) && (f[29] || !f[24] || !f[22]) && (!f[37] || f[38] || f[28]);
}

static int policy_c(const int *f) {
    return (f[27] || f[39] || f[37]) && (!f[20] || !f[35] || !f[38]) && (!f[32] || f[36] || !f[28]) &&
           (!f[22] || f[33] || !f[29]) && (f[30] || !f[35] || !f[32]) && (f[26] || f[21] || !f[24]) &&
           (f[24] || f[29] || f[21]) && (f[31] || !f[36] || f[28]) && (f[31] || !f[23] || f[38]) &&
           (f[32] || f[24] || !f[27]) && (!f[21] || f[28] || f[33]) && (!f[36] || !f[29] || f[33]) &&
           (!f[39] || f[29] || f[35]) && (!f[32] || !f[33] || !f[21]) && (f[23] || f[38] || !f[20]) &&
           (!f[25] || !f[35] || f[20]) && (!f[30] || f[34] || !f[28]) &&
           (!f[38] || !f[27] || !f[36]) && (!f[28] || !f[34] || f[20]) && (f[25] || f[22] || f[33]) &&
           (!f[28] || !f[27] || f[25]) && (!f[28] || !f[20] || f[31]) && (f[32] || !f[30] || !f[28]) &&
           (!f[28] || f[33] || !f[32]) && (f[30] || !f[35] || !f[27]) &&
           (!f[34] || !f[24] || !f[27]) && (f[23] || f[32] || f[25]) && (!f[30] || !f[29] || f[23]) &&
           (f[26] || f[37] || !f[24]) && (!f[25] || !f[31] || !f[32]) && (!f[35] || f[23] || f[26]) &&
           (!f[38] || f[31] || f[35]) && (!f[20] || f[23] || !f[29]) && (!f[31] || !f[25] || f[28]) &&
           (f[33] || !f[24] || !f[25]) && (f[31] || !f[34] || !f[33]) &&
           (!f[20] || !f[30] || !f[29]) && (f[26] || !f[29] || f[32]) && (f[34] || f[30] || !f[24]) &&
           (!f[28] || f[31] || f[21]) && (!f[20] || !f[34] || !f[39]) &&
           (!f[27] || !f[28] || !f[36]) && (!f[29] || f[37] || f[35]);
}

static int policy_d(const int *f) {
    return (f[40] || f[53] || !f[48]) && (f[57] || !f[56] || !f[44]) && (!f[41] || !f[59] || !f[44]) &&
           (f[58] || f[59] || f[55]) && (f[41] || f[46] || !f[53]) && (f[42] || !f[50] || !f[45]) &&
           (f[40] || !f[50] || f[52]) && (!f[53] || !f[58] || !f[50]) && (f[44] || f[53] || !f[56]) &&
           (f[44] || !f[53] || f[40]) && (f[58] || f[52] || !f[40]) && (f[45] || f[59] || !f[41]) &&
           (!f[47] || f[45] || !f[46]) && (!f[50] || f[40] || !f[43]) && (!f[58] || f[51] || !f[45]) &&
           (!f[59] || !f[58] || !f[46]) && (!f[54] || f[48] || !f[41]) &&
           (!f[42] || !f[44] || f[58]) && (!f[46] || f[47] || !f[43]) && (!f[40] || f[57] || !f[49]) &&
           (!f[54] || f[40] || f[52]) && (f[44] || !f[46] || !f[54]) && (!f[42] || f[48] || !f[45]) &&
           (!f[56] || f[52] || f[41]) && (!f[51] || !f[44] || f[58]) && (f[48] || !f[47] || !f[42]) &&
           (f[57] || !f[52] || f[44]) && (!f[49] || f[42] || !f[54]) && (f[57] || !f[55] || !f[56]) &&
           (!f[46] || f[40] || !f[41]) && (!f[54] || f[44] || f[45]) && (!f[50] || !f[52] || !f[56]) &&
           (f[53] || !f[43] || f[57]) && (f[53] || f[49] || f[57]) && (!f[40] || f[50] || !f[51]) &&
           (f[56] || !f[48] || !f[54]) && (f[58] || !f[56] || f[46]) && (f[47] || f[44] || !f[51]) &&
           (!f[51] || !f[55] || !f[53]) && (!f[56] || !f[40] || f[52]) &&
           (!f[42] || !f[57] || f[52]) && (f[48] || f[43] || f[42]);
}

static int policy_e(const int *f) {
    return (f[48] || !f[55] || f[45]) && (!f[46] || f[56] || f[57]) && (f[59] || f[52] || !f[57]) &&
           (f[54] || !f[47] || f[57]) && (!f[55] || f[41] || !f[58]) && (!f[43] || !f[57] || !f[49]) &&
           (!f[45] || !f[49] || f[50]) && (f[52] || !f[53] || !f[56]) && (f[46] || f[48] || !f[58]) &&
           (!f[58] || !f[54] || f[45]) && (f[52] || f[54] || !f[48]) && (f[49] || f[42] || f[51]) &&
           (f[54] || !f[46] || !f[41]) && (!f[55] || f[42] || f[57]) && (!f[43] || f[45] || f[46]) &&
           (!f[50] || f[45] || !f[57]) && (!f[47] || !f[48] || !f[53]) &&
           (!f[52] || f[48] || !f[40]) && (f[57] || f[40] || f[43]) && (!f[42] || !f[55] || !f[54]) &&
           (!f[58] || !f[59] || !f[53]) && (!f[46] || !f[47] || !f[56]) &&
           (f[47] || !f[42] || !f[50]) && (!f[53] || !f[50] || !f[56]) && (!f[58] || f[51] || f[46]) &&
           (!f[42] || !f[44] || !f[56]) && (f[52] || !f[46] || !f[45]) && (f[51] || f[43] || !f[55]) &&
           (f[57] || f[49] || !f[46]) && (!f[44] || f[52] || !f[55]) && (!f[58] || !f[51] || f[45]) &&
           (f[45] || f[59] || f[49]) && (f[55] || !f[54] || !f[41]) && (!f[44] || !f[48] || f[40]) &&
           (f[43] || f[59] || f[48]) && (!f[47] || !f[55] || f[51]) && (!f[54] || !f[51] || !f[58]) &&
           (!f[43] || f[52] || !f[46]) && (!f[51] || !f[47] || f[48]) && (f[56] || f[50] || f[43]) &&
           (f[49] || !f[55] || f[45]) && (f[43] || !f[48] || f[55]) && (!f[47] || !f[54] || !f[57]);
}

/* Build-profile diagnostics. */
static const unsigned int slot_weights_a[138][6] = {
    { 0x7184d454u, 0x95bd447eu, 0x84e61cebu, 0x62f746b4u, 0x4b2d451cu, 0xb80469b8u },
    { 0x36824dd6u, 0xb61e6ba5u, 0x2399d29du, 0x6ae12c97u, 0x1b2ba06bu, 0xec7ac8adu },
    { 0xf5b19f71u, 0x6ca4a1a9u, 0x2248cd70u, 0xdc36fc90u, 0x2052e52bu, 0x4f0f4c3cu },
    { 0x37b00307u, 0xe500bddfu, 0x778e6176u, 0x5e0e14cau, 0xda2ec003u, 0x54a5054cu },
    { 0x281fa6f5u, 0x953a5154u, 0xa84567f9u, 0x8c0a70a7u, 0x4c83cf3bu, 0x169a73bfu },
    { 0x4c8edfa3u, 0x0db317d9u, 0x1dc02e27u, 0xb71ed78au, 0x588efbceu, 0x939ae232u },
    { 0xe844c762u, 0xc85990d2u, 0x66c164e7u, 0x5e571eaau, 0x5097c040u, 0x60ec6db2u },
    { 0xb0992bcfu, 0x5df6f817u, 0x5e5c4176u, 0x03f84c48u, 0xc6a942d3u, 0x8c3f846cu },
    { 0x96d38ff5u, 0x3da9d8c0u, 0x5a661477u, 0x3af9f30cu, 0x6ed91f2eu, 0x7ec0c922u },
    { 0x0ded97bbu, 0xbaa2919cu, 0x6be994f2u, 0x5e05c990u, 0x0b4702d2u, 0x9ce4aa5fu },
    { 0xde27387cu, 0x851bec1eu, 0x862a73dbu, 0x50d00787u, 0xd4381551u, 0x7ac526d3u },
    { 0x7582329fu, 0x7a8d9ccdu, 0xfc80fa6fu, 0x620602e0u, 0x45d28c06u, 0x670c5891u },
    { 0xa386c4a7u, 0x5eda7e46u, 0x00e287d7u, 0xbce1cb34u, 0x936b7ac2u, 0xbaeebb48u },
    { 0xf910d68au, 0x7592b89fu, 0x09ff7f0cu, 0x8434d99cu, 0x4eaf6d61u, 0xa9cc2ff7u },
    { 0xf0ae1284u, 0x1b2410a6u, 0x3418a2c5u, 0x944782d7u, 0x2ba33d67u, 0xc074a644u },
    { 0xd2ab5d67u, 0x101379c7u, 0x27801375u, 0xdecf9580u, 0xc9f28a8au, 0x543bcfbbu },
    { 0x4865d3eeu, 0xb85993a7u, 0x56364be9u, 0x6d84cc79u, 0x214119cfu, 0x060bed79u },
    { 0x0bdcb5d3u, 0xfe2fbd72u, 0xc7fda173u, 0x7ff959b7u, 0x4233eb55u, 0x04948682u },
    { 0x46b1f9d2u, 0xb1e9f4fdu, 0x12fcce59u, 0x2ccd5f71u, 0xb938eca4u, 0x037b1bf3u },
    { 0xec32db3bu, 0x1404cd3au, 0x0f06e36bu, 0xe910fc8du, 0x46635a99u, 0x603ae5dau },
    { 0x3dde8fcbu, 0xbda03923u, 0xfb68eb68u, 0xd4ae6af5u, 0x9f6d26b2u, 0x4fba675du },
    { 0x0d9792c1u, 0x5b391664u, 0x8d301cafu, 0x0d5feb54u, 0x22aab6feu, 0xe8948dc3u },
    { 0x1ee6db62u, 0xedeed739u, 0x0822e8e7u, 0x5d0991e0u, 0x02228d48u, 0x37c3de4cu },
    { 0x2a848829u, 0x8b21ea85u, 0x0346ce06u, 0x7ac0cddbu, 0x8a624ac1u, 0xc199c0a9u },
    { 0xdf8adf39u, 0x627d239fu, 0xa8eb52f1u, 0x4ca8c324u, 0xedd03c87u, 0x88b6350eu },
    { 0xeef6aac4u, 0xd9fb18e8u, 0x80f485eau, 0x6895bc43u, 0x8f18de53u, 0xf7572dd8u },
    { 0xb93e295fu, 0x53623b53u, 0x52608ba9u, 0x95814675u, 0x76886726u, 0x0999f495u },
    { 0x1aafd366u, 0xdde5a881u, 0x8a01f57au, 0x19b343bbu, 0xf9a8eab8u, 0x1007e910u },
    { 0x5e200159u, 0x6518182bu, 0x724a67f6u, 0xe4d3921au, 0x3e21b31du, 0xa9225a7du },
    { 0x54e66454u, 0x2936be1au, 0xc6e5ff4du, 0x0e5c6000u, 0xd75762efu, 0x9e6a1947u },
    { 0xe15b72c2u, 0xc4806bd0u, 0xbf76e314u, 0x54a8dc38u, 0x7e2d1302u, 0xa45c8f2du },
    { 0x6b9156e7u, 0x49469a5eu, 0xe5e5b240u, 0xfe030f59u, 0xe4ec9f0du, 0xcb9b515fu },
    { 0xa5c46004u, 0x8eeb4467u, 0x5974cf6bu, 0x479dd02eu, 0x768c6714u, 0x0dfed74bu },
    { 0x8ba060f1u, 0xa35ffc5bu, 0x6fb35c13u, 0x6e2d3c61u, 0x4cca838cu, 0xcac858bbu },
    { 0xf201da49u, 0xc861f3a5u, 0xac59c7b6u, 0xe465b1f1u, 0xff35f810u, 0xd42a4dafu },
    { 0x699fe62au, 0x2d9cf439u, 0x3ce468a1u, 0x4fee8d49u, 0xb36f4c48u, 0x08d01bfeu },
    { 0xcef350e7u, 0x8ef5b163u, 0x58b8413fu, 0xa15f09c8u, 0x2b1522b8u, 0xa6e35f4bu },
    { 0xd3f1b773u, 0x04a0a7d3u, 0x0a6fd693u, 0xf2ecb7d9u, 0x805913eeu, 0x6c5421f1u },
    { 0x375277c6u, 0x3ece2523u, 0x807d2f89u, 0x45b58f3au, 0x2ef18a65u, 0xf0510649u },
    { 0x9c52e09cu, 0x6a84e8d5u, 0x068189f4u, 0xb47ae101u, 0xd66b4b4du, 0x7ead13ffu },
    { 0xb8ea1882u, 0x2fa8a1efu, 0xa9533ae2u, 0xcd64fb1eu, 0x3b63cd5fu, 0x69a09cb0u },
    { 0xafe16f01u, 0x655f32b3u, 0x1f4ee209u, 0x15743f59u, 0x8c346fa1u, 0xc0edbe71u },
    { 0x51799876u, 0xa61b8500u, 0xbf50f9a6u, 0xe3f6673cu, 0x7d57a798u, 0x1f64a68eu },
    { 0x48aeb4ebu, 0xaf3a233du, 0x985fa535u, 0x197f957fu, 0xabce3acdu, 0x2e9e066du },
    { 0x07ddd33du, 0x2d30cb03u, 0x45dc3232u, 0xf1977fd6u, 0xd9d23777u, 0x4e0ca487u },
    { 0xa184db17u, 0x7e40434au, 0x217c384du, 0x683337d3u, 0x3bc4bb7du, 0x95b97bd7u },
    { 0x93842ea6u, 0x5251802du, 0xa5c29302u, 0xa7753e56u, 0x611fd5b0u, 0xa8d43ad8u },
    { 0xd6ca839bu, 0x47cad8c0u, 0x8b7206dau, 0x87d8b1ebu, 0x9ddac466u, 0xf8784ccfu },
    { 0xa2e8f6e0u, 0x27f293f2u, 0x82df3d8fu, 0x2585a1a5u, 0xf4b39363u, 0xfc2d8829u },
    { 0x2c282fbcu, 0x10a13d91u, 0xd2ee78c5u, 0xf9566269u, 0x256d0495u, 0xf502b6a0u },
    { 0x3784e1fau, 0xc66f511bu, 0xcd7e90b2u, 0xd79834c3u, 0x92e3d3f0u, 0x1c62f04cu },
    { 0x7f7db327u, 0x14eb9e58u, 0x7afa1571u, 0x0fbf9224u, 0xaf91e1beu, 0x2a5dd92eu },
    { 0xa5dab41eu, 0x91c5fb2bu, 0x75ce603cu, 0x56e91eccu, 0x6e472364u, 0x7288ad31u },
    { 0xf3323cb4u, 0xb788c2b1u, 0x1550ec46u, 0x7ac796a5u, 0x990e011eu, 0x56f36db8u },
    { 0x10d18958u, 0x4c6ce987u, 0xea825d63u, 0x09518465u, 0x832af3b7u, 0xfa7f2f8au },
    { 0x32dadaebu, 0x0d0b7738u, 0x65331798u, 0x8f529c69u, 0x9c8996afu, 0x9f7499eau },
    { 0xb34f6f7bu, 0x9bc84625u, 0xfaeb6e80u, 0x7d5ead2au, 0x509e257du, 0x9ee131a4u },
    { 0x8f429beau, 0xe05309dcu, 0xa0002c4du, 0x524b3e7fu, 0xad6064cfu, 0x046f02a4u },
    { 0x6b300be7u, 0x7392d418u, 0xe9b27c69u, 0x72143c59u, 0x42a67cd2u, 0x34bde85bu },
    { 0x24604075u, 0x1a61de45u, 0x5f4bce51u, 0x3bfa5ca2u, 0x8ced402fu, 0xbad06c27u },
    { 0xd19e2413u, 0x076de7f8u, 0xbd9831d4u, 0xfc9b254cu, 0x1880979eu, 0xbc1be6c6u },
    { 0xf6783119u, 0xa20157fbu, 0x72e831dfu, 0x55362e21u, 0x872733dfu, 0x7dc2aec4u },
    { 0x61d3a995u, 0xe7755221u, 0xfb55b3cdu, 0x05d57c27u, 0x082a5b63u, 0xc8cb7fe0u },
    { 0x4dff96d9u, 0x981d83f0u, 0xc8ac45f0u, 0x28a46960u, 0xceabdb38u, 0x924796b7u },
    { 0x4564f5bdu, 0x33aee0b1u, 0xb23f1435u, 0x20aa2891u, 0xece135bcu, 0x4ae79162u },
    { 0xa93db3ebu, 0x23461c9bu, 0xf80a1434u, 0x958e7ff2u, 0xee7fc5e3u, 0xf2a9be44u },
    { 0x29fd4ec3u, 0x08f89399u, 0x815e23f0u, 0xd7d0d48fu, 0x94acde30u, 0x64eb6f28u },
    { 0xfcb6cfddu, 0x7bb3a422u, 0x7cde1af1u, 0x2d95ee4cu, 0xb440b8acu, 0x8a4bbe47u },
    { 0xa4960f45u, 0x7c1171cdu, 0x17ca6af2u, 0xb28d3231u, 0xb28cda7du, 0x474b98b7u },
    { 0xb39b5bb1u, 0x0979d283u, 0x4235cf60u, 0x1aeb5465u, 0xf6d3259eu, 0xd82d4814u },
    { 0x740f3ff9u, 0xdb0720deu, 0x6b5ec28au, 0x7fd3cab2u, 0xf9424c73u, 0x0c744f85u },
    { 0x57e8e91bu, 0xa86e653bu, 0x4580daa6u, 0xa5e833b6u, 0x7a61ac32u, 0x77e90a87u },
    { 0xb442bc2bu, 0x5e26445fu, 0x573ae0d9u, 0xbcf933b6u, 0x905a71c1u, 0x09ba7970u },
    { 0xb5304e20u, 0x4535a84au, 0x5f241dc6u, 0x818a4e74u, 0xb03b8bdcu, 0xf7429761u },
    { 0xf226d5e6u, 0x70a95218u, 0xc407406cu, 0x97971ae3u, 0x5a13392bu, 0x4683f165u },
    { 0x6a2684f9u, 0x552fefcdu, 0x5619f21bu, 0xc8350ef1u, 0x63b94387u, 0x36e4962du },
    { 0xc582ad31u, 0xcc81f95au, 0x50322a1bu, 0x105d786fu, 0x3cdaafd8u, 0x47a609f1u },
    { 0x02131e45u, 0x2baa1d22u, 0x9fc26d73u, 0x69e2d31au, 0xd9460577u, 0x51b39184u },
    { 0x6a85a5efu, 0x51134e11u, 0xb1315805u, 0xb5ba04ffu, 0x4393262eu, 0xa3a0921fu },
    { 0xeb544768u, 0xd6924459u, 0xb06a4e72u, 0x6fea9d38u, 0x664ee356u, 0x192d488fu },
    { 0xc09a4c26u, 0xd0d95517u, 0x51d43503u, 0x6c8ba840u, 0xbc306607u, 0x3dde8126u },
    { 0xf5baaca6u, 0x9483afa0u, 0xc40fb411u, 0xe4bd580au, 0xc54bea22u, 0x4f59da37u },
    { 0x64b6021bu, 0x44aa5d73u, 0xe393c9a8u, 0xab94af63u, 0xc59b3082u, 0x541c956au },
    { 0xd0934363u, 0xfec7a19cu, 0xde9d491du, 0xafff73acu, 0x231be2b5u, 0xce45ed9du },
    { 0x50007e87u, 0xf02e6666u, 0xc30cb97cu, 0x3eb0e136u, 0xb0e8551du, 0x84ecf327u },
    { 0xd345232eu, 0x666e86ffu, 0xf49c8f9cu, 0xa0bce7e2u, 0x4ae8461eu, 0x417262c1u },
    { 0xed97d666u, 0xab297ba0u, 0x3f3f3707u, 0x0a96c26au, 0x3ae84435u, 0xa1fa15c7u },
    { 0x3fe25e67u, 0x24b5a833u, 0x147e556au, 0x93c30046u, 0x15b7f6aeu, 0x7034bf1fu },
    { 0xb8f098b7u, 0x72339620u, 0x4daafcd1u, 0x44dc6957u, 0x22375d32u, 0x53624b67u },
    { 0x6dba6befu, 0x60948f1fu, 0x50fcf8deu, 0x67a41c39u, 0x6b05178fu, 0x2ac6565cu },
    { 0x0a10d948u, 0xb65fd554u, 0xcf03bacau, 0x958c42b8u, 0x3d6523e6u, 0x6a77b460u },
    { 0x2d382cd3u, 0xc295f460u, 0x2d171ec8u, 0xcb32e7dcu, 0x884c6264u, 0x3e29bb63u },
    { 0x9056acc6u, 0xb07df7b6u, 0x6043f080u, 0x18e2a749u, 0x049404d9u, 0x934f61bcu },
    { 0x1a5b7829u, 0x39b40511u, 0x4a7951b0u, 0x35243ff8u, 0xfa1eafaeu, 0xdcb152b0u },
    { 0x5c3a34f5u, 0x55aa024du, 0xd6a754aau, 0x02a4f786u, 0x077e26d9u, 0xb65b83f5u },
    { 0x02da7e5du, 0x25eb5b33u, 0xa9ad9a61u, 0x9c4cde11u, 0xce864060u, 0x1b2fdb78u },
    { 0xbf3c10a7u, 0x47379950u, 0xa375056fu, 0x1dbb7350u, 0xe89ed3f9u, 0x927e1718u },
    { 0x775697b9u, 0x2d7be4c3u, 0xd663730cu, 0x77e0cfd8u, 0xc856cfd2u, 0x32391bfbu },
    { 0xb0c1cb8du, 0x285fd2deu, 0x98df9f2au, 0xa96ce36au, 0x61453438u, 0x381c539eu },
    { 0x082682afu, 0xa7f4d00au, 0x320e9208u, 0x04e7157du, 0x3b852844u, 0x8457dd3cu },
    { 0x3ee8d979u, 0xfaeb878bu, 0x28da675bu, 0xe8e45097u, 0x8010fb58u, 0xa31e19b4u },
    { 0xb2ca20fcu, 0xd02458a5u, 0x285c266eu, 0xeaac2219u, 0x51d4569cu, 0x6809fef1u },
    { 0x0cd6c6c2u, 0x956e0c50u, 0xa5e4357fu, 0xc2f224f8u, 0x297f8ed4u, 0x3518b376u },
    { 0xabf2e752u, 0xa901d574u, 0x178177fcu, 0x05a09a0fu, 0xd41fe385u, 0x85182ca0u },
    { 0x81b5b04bu, 0x194cbad4u, 0xdfb68c9bu, 0x1e4702a1u, 0xdcdd2eb9u, 0x7b22d383u },
    { 0xf164ad06u, 0xf174e866u, 0x85bc7691u, 0x215546f9u, 0xfa354208u, 0xebe43d9eu },
    { 0x1059179fu, 0x7ea66ad8u, 0x4196fb30u, 0xf0dd04ffu, 0xf7a493fau, 0x0cbebe84u },
    { 0x2cb49c7fu, 0xcdda02d8u, 0xa5e3df0au, 0xa9d3bc53u, 0x85f13b58u, 0x36dec5b4u },
    { 0xce4e1b01u, 0x3ac1dd50u, 0x5f67a20du, 0x8fe59b17u, 0x62229e15u, 0x7725a768u },
    { 0x3c1ac73cu, 0x06a87e4eu, 0x2bc45c5bu, 0x49225a1du, 0x8c3eb751u, 0x9899602du },
    { 0xfc1b8cb2u, 0x7b82f5d5u, 0x9c9a07b8u, 0xdb276525u, 0x3b6bda09u, 0x5454adcdu },
    { 0x0c34953fu, 0xd1add81du, 0xad8e9be7u, 0x9cfc9058u, 0x2e3adf07u, 0x5662ccdeu },
    { 0x73a204c6u, 0x27c5406bu, 0x49326a5au, 0x6c4b92f1u, 0x29a7a565u, 0xe1c85c62u },
    { 0x99461b04u, 0x35c72de8u, 0xf319cb72u, 0x33c2f758u, 0x42fd9418u, 0x6ca98888u },
    { 0x0c25ae96u, 0xb33cdaf9u, 0xa0c6c419u, 0x2d045b09u, 0xaa86b608u, 0x36a28c1fu },
    { 0x5e85d8deu, 0x227c8432u, 0x5473e90eu, 0xc449100du, 0xdf69c61bu, 0xd12239ecu },
    { 0xb34feb37u, 0xa0169332u, 0x5c6418c7u, 0xc8b0afeau, 0xa98c53e4u, 0x539f2cbdu },
    { 0x9d9f58a7u, 0x2ac47fe9u, 0xdb791d5du, 0xc0f3451cu, 0x6efa36b8u, 0xdfb98030u },
    { 0xab85ac7eu, 0x4605e29fu, 0xc77120ddu, 0x9208b78eu, 0xc1d8c14bu, 0xc0c39117u },
    { 0x01e7b191u, 0x3c77574cu, 0xd02ea8f7u, 0x18fa69fcu, 0xde44cb23u, 0x43466395u },
    { 0xb588f3a3u, 0x2e841996u, 0x696ab050u, 0xcec12a12u, 0x2b58b54fu, 0x90cb94aeu },
    { 0xdb5c75c6u, 0xbd72b8a0u, 0xdf0bfcf5u, 0xdc0ba194u, 0xbf46fbceu, 0xd9b0601du },
    { 0x3989b98cu, 0x28a60a2cu, 0x1b1987b4u, 0x1fa3f273u, 0xcd55d0d6u, 0x47268ea4u },
    { 0x3d02d8f9u, 0x03403ff7u, 0x192cbaa2u, 0xb6cc699eu, 0x96e85ccdu, 0xf1e5bc24u },
    { 0x803e9fc9u, 0x72c72220u, 0x8b26b869u, 0xcd46812au, 0x4ed31894u, 0xb22f098fu },
    { 0x22ced431u, 0x5d13d549u, 0xe1111d7au, 0xb9da42d6u, 0xcfb067c4u, 0x6e55d7b3u },
    { 0x063eed82u, 0xf1f76a38u, 0x009f46dfu, 0xdab455f2u, 0xff06e4a0u, 0x567fd113u },
    { 0x792f5c17u, 0x4b888ca8u, 0xf3ac284eu, 0xd625ede2u, 0xcb53879eu, 0xdf9459cdu },
    { 0x3b632b9bu, 0x0f84264eu, 0x62a916f6u, 0x197ea090u, 0xf56b25bfu, 0x60ff0b5eu },
    { 0xd9009507u, 0xf0b7fbc2u, 0xbc1930a5u, 0x9a488826u, 0x9713386bu, 0xe945f50au },
    { 0x352e81e7u, 0xc0d22e35u, 0x56b8b55cu, 0x72f30502u, 0x57d7b723u, 0x3f9dcafeu },
    { 0x42cf7d7au, 0xdaa237b2u, 0x9700e05au, 0xb219360fu, 0xae1cdcd3u, 0x6f062712u },
    { 0x70a8a7b2u, 0x4c1116b5u, 0x0e2668b1u, 0x7bfe37bau, 0x42d07ec4u, 0x0c203c15u },
    { 0x4a12fa6fu, 0xec478428u, 0x5c884f62u, 0xf9667fccu, 0x52bdc332u, 0x20a16243u },
    { 0x6a518371u, 0x215453c3u, 0xbc06ae7fu, 0x7e35a51eu, 0xa4a3907bu, 0x13dc085au },
    { 0xe2b467beu, 0x2b3830cfu, 0x1d45595du, 0x5bda60e3u, 0x3848e4fbu, 0xb0b34722u },
    { 0xe000d32eu, 0x561a8d80u, 0x60b261b9u, 0xa8ebe381u, 0x41c9ffb8u, 0x206558bau },
    { 0xa6da1b07u, 0x28226abcu, 0xfd16153du, 0x18354577u, 0xd5ae094fu, 0x42f82559u },
};

static unsigned int slot_mix_a_00(unsigned int x) {
    x = (x << 7) | (x >> 25);
    x *= 0x85ebca6bu;
    x ^= x >> 16;
    return x;
}

static unsigned int slot_mix_a_01(unsigned int x) {
    x ^= 0xc2b2ae35u;
    x = (x >> 3) | (x << 29);
    x += 0x165667b1u;
    return x;
}

static unsigned int slot_mix_a_02(unsigned int x) {
    x = (x << 7) | (x >> 25);
    x *= 0x85ebca6bu;
    x ^= x >> 16;
    return x;
}

static unsigned int slot_mix_a_03(unsigned int x) {
    x += 0x7ed55d16u;
    x ^= x << 5;
    x ^= x >> 11;
    return x;
}

static unsigned int slot_mix_a_04(unsigned int x) {
    x ^= x >> 13;
    x *= 0x9e3779b1u;
    x ^= x >> 7;
    return x;
}

static unsigned int slot_mix_a_05(unsigned int x) {
    x ^= x >> 13;
    x *= 0x9e3779b1u;
    x ^= x >> 7;
    return x;
}

static unsigned int slot_mix_a_06(unsigned int x) {
    x = (x << 7) | (x >> 25);
    x *= 0x85ebca6bu;
    x ^= x >> 16;
    return x;
}

static unsigned int slot_mix_a_07(unsigned int x) {
    x ^= x >> 13;
    x *= 0x9e3779b1u;
    x ^= x >> 7;
    return x;
}

static unsigned int slot_mix_a_08(unsigned int x) {
    x += 0x7ed55d16u;
    x ^= x << 5;
    x ^= x >> 11;
    return x;
}

static unsigned int slot_mix_a_09(unsigned int x) {
    x = (x << 7) | (x >> 25);
    x *= 0x85ebca6bu;
    x ^= x >> 16;
    return x;
}

static unsigned int slot_mix_a_10(unsigned int x) {
    x ^= x >> 13;
    x *= 0x9e3779b1u;
    x ^= x >> 7;
    return x;
}

static unsigned int slot_mix_a_11(unsigned int x) {
    x ^= 0xc2b2ae35u;
    x = (x >> 3) | (x << 29);
    x += 0x165667b1u;
    return x;
}

static unsigned int slot_mix_a_12(unsigned int x) {
    x ^= 0xc2b2ae35u;
    x = (x >> 3) | (x << 29);
    x += 0x165667b1u;
    return x;
}

static unsigned int slot_mix_a_13(unsigned int x) {
    x = (x << 7) | (x >> 25);
    x *= 0x85ebca6bu;
    x ^= x >> 16;
    return x;
}

static unsigned int profile_digest_a(const int *f, int n) {
    unsigned int h = 0x811c9dc5u;
    int i;
    for (i = 0; i < n; i++) {
        h = (h * 16777619u) ^ (unsigned int)f[i];
    }
    h = slot_mix_a_00(h ^ slot_weights_a[0 % 138][0]);
    h = slot_mix_a_01(h ^ slot_weights_a[1 % 138][1]);
    h = slot_mix_a_02(h ^ slot_weights_a[2 % 138][2]);
    h = slot_mix_a_03(h ^ slot_weights_a[3 % 138][3]);
    h = slot_mix_a_04(h ^ slot_weights_a[4 % 138][4]);
    h = slot_mix_a_05(h ^ slot_weights_a[5 % 138][5]);
    h = slot_mix_a_06(h ^ slot_weights_a[6 % 138][0]);
    h = slot_mix_a_07(h ^ slot_weights_a[7 % 138][1]);
    h = slot_mix_a_08(h ^ slot_weights_a[8 % 138][2]);
    h = slot_mix_a_09(h ^ slot_weights_a[9 % 138][3]);
    h = slot_mix_a_10(h ^ slot_weights_a[10 % 138][4]);
    h = slot_mix_a_11(h ^ slot_weights_a[11 % 138][5]);
    h = slot_mix_a_12(h ^ slot_weights_a[12 % 138][0]);
    h = slot_mix_a_13(h ^ slot_weights_a[13 % 138][1]);
    return h;
}

static size_t table_bytes(int count, int s1) {
    if (s1 == 1) {
        int narrow = count * (int)sizeof(int);
        return (size_t)narrow;
    }
    return (size_t)count * sizeof(int);
}

/* Build-profile diagnostics. */
static const unsigned int slot_weights_b[138][6] = {
    { 0xf0480ff9u, 0x86dc283cu, 0x2cb6916du, 0x47eaa099u, 0x593942a4u, 0xca118783u },
    { 0x9bf13331u, 0x1509bb0au, 0x56670b14u, 0x12e1bc76u, 0x01088475u, 0xf5ec52edu },
    { 0x2e416788u, 0x2909406cu, 0x5c906158u, 0x59ba1b0du, 0x2bb29976u, 0x2a095ee8u },
    { 0x985fb4e7u, 0x5d32fe61u, 0x64c7a500u, 0x59e2d153u, 0x58151a99u, 0x9a1e40b4u },
    { 0xe693ae2du, 0x1d8a4eacu, 0x3eaabe17u, 0x68b4aef7u, 0xeb04b39bu, 0x13e783e7u },
    { 0x78068577u, 0x142c8364u, 0x53fe2e85u, 0x260df254u, 0x178854f2u, 0x3b041641u },
    { 0xadd9ca88u, 0x35c719c2u, 0x5ed8abccu, 0x00a154d8u, 0xe8e3574fu, 0x59ec8712u },
    { 0x855dbf55u, 0xc0290103u, 0xdcb0b82eu, 0xe7949b80u, 0xa4ff91e3u, 0x6e704245u },
    { 0x06762832u, 0x37a788d1u, 0x320a88eau, 0xde1b1471u, 0x9ddbef12u, 0x2cd552a0u },
    { 0x21e52f21u, 0x4350cc17u, 0x9ec04eceu, 0xb600e612u, 0xd6846325u, 0x9ed89eddu },
    { 0x5ee347ddu, 0xe34acb11u, 0x5fac9cb6u, 0x627bf322u, 0x6f2c7a8cu, 0xee889fe4u },
    { 0x9545f0f3u, 0xa930d55du, 0xe339d309u, 0x75927b0fu, 0x6e85df08u, 0x43f2f193u },
    { 0x84e0164bu, 0x050c86bdu, 0x381df22fu, 0x990d3cd8u, 0xb0cdf20au, 0xfcc1c0c8u },
    { 0x3e7fb97bu, 0xe07cb579u, 0x77ca4499u, 0xb5c34e7eu, 0x86ea0214u, 0x78f6d824u },
    { 0x655c1d15u, 0x7b7e8913u, 0x761e07cbu, 0x1dcd327fu, 0xdbc52933u, 0xa92fa271u },
    { 0x7fed0bb9u, 0x9672be1au, 0xbdbcda98u, 0x5cbe4f50u, 0xcf25e346u, 0xc44a66f4u },
    { 0xb18fbdb1u, 0x134b8db4u, 0x6470ff1fu, 0x1e2ed6cbu, 0x761978ddu, 0x57e485b6u },
    { 0xfdf0a45fu, 0x4f859933u, 0xfd0b00eau, 0xd9855162u, 0x18949a23u, 0x2e460a96u },
    { 0xf376bc25u, 0x4ea9877au, 0xec9a72f2u, 0x310a853eu, 0x43c20f56u, 0x01f72b0au },
    { 0x93a9b8b6u, 0x64e752ccu, 0x5fd11a32u, 0x7a674d0au, 0xcf00377cu, 0xbbb3a32au },
    { 0x4ed3d99eu, 0x505bdd8fu, 0x07d3b36cu, 0x79ded9f2u, 0xee6f7a8fu, 0xad783715u },
    { 0xe771876eu, 0x8a9e1df7u, 0x228a3129u, 0x69fa541cu, 0xc37ee1e2u, 0x9e180bf5u },
    { 0x926271f2u, 0xb4a37b2bu, 0x8e9e7bb8u, 0x20b81d7fu, 0x84c6a400u, 0xc7f336dau },
    { 0xafd838d3u, 0xaafaf84bu, 0x8913c782u, 0x838e4a11u, 0x79b58a73u, 0x38bf8cc2u },
    { 0xd3f28783u, 0x7df3bae7u, 0x19a7bae4u, 0xd38cf734u, 0xc2b8c1c5u, 0x5804abbeu },
    { 0x1055ab62u, 0x61796ac4u, 0x4dee94f9u, 0x3f28bbfau, 0xbe61dea4u, 0x95655d03u },
    { 0x402db603u, 0xa64b88b0u, 0x060d5a21u, 0xe5600642u, 0x0a6bf830u, 0xfee7a16bu },
    { 0x99181b1du, 0x3c0eea66u, 0x2bac7c60u, 0xa0cda017u, 0x9f6f4756u, 0xefdeed7fu },
    { 0xe3221553u, 0xba9153bdu, 0xe2f04826u, 0xfb474e95u, 0xcac733f4u, 0x76d4d9b1u },
    { 0xe3923fcdu, 0x980f951cu, 0x902456cfu, 0xbd3f3fbfu, 0x1d3183abu, 0x7acfa1b6u },
    { 0xbaaa7b43u, 0x7e127b35u, 0x9b3904c1u, 0xe85a57fcu, 0xb644c0feu, 0xcc411c6du },
    { 0xad52b3c3u, 0x4e64eff0u, 0xaca93b03u, 0xddb88d09u, 0xfe279f1au, 0xbfbfc1d9u },
    { 0x4d719ec7u, 0x0ff8330cu, 0xa7c35599u, 0x42eb80dcu, 0x7ea2fb2bu, 0x1392e452u },
    { 0xf0494dc0u, 0xc1a1dbfdu, 0x0bd47e27u, 0x4e6833ebu, 0xb3140f25u, 0x88aaeb7cu },
    { 0xa30abf65u, 0x0f6592a5u, 0xb2b130dau, 0x33c6a5a5u, 0x0d5e92c8u, 0x9c644f95u },
    { 0x87a2babdu, 0x372c4235u, 0x0b39b779u, 0x090da4fcu, 0x33676dd4u, 0x6379e369u },
    { 0xce9001efu, 0x3a322062u, 0x3797120bu, 0x2a868409u, 0xa5b5c578u, 0xe64f74feu },
    { 0x81e8ea41u, 0xcb80142cu, 0x8b36cd0cu, 0xafc52a09u, 0x2a33017du, 0x4c02aa64u },
    { 0xe6c39385u, 0x4ba170c9u, 0x45d1349au, 0x2c75bf61u, 0xf97bf1b8u, 0xb258c319u },
    { 0x85f5547au, 0x14c7fc1cu, 0xc1465919u, 0x83f7fbb2u, 0xc5428767u, 0xd26d4b5au },
    { 0x1d4756cbu, 0xf4ab769eu, 0x8e9f0526u, 0x92c3bfeeu, 0x9fbc5e01u, 0xed0375b4u },
    { 0x79e15c25u, 0xf82b08eau, 0xda86430au, 0xf345ea49u, 0x450575f3u, 0xe0776f79u },
    { 0x50295142u, 0x3586b1ffu, 0x89b44b2du, 0x72defbc6u, 0x87b112e8u, 0x3bbdae46u },
    { 0xd517d4d0u, 0x305a34bau, 0xc8daa038u, 0xaa2264acu, 0xf61e86e9u, 0x42569925u },
    { 0x6c3b8027u, 0xda40515eu, 0xe0004d36u, 0x1afd72aeu, 0xa5383ca5u, 0x9deeaa9cu },
    { 0xfa4aaa5bu, 0xc682edf6u, 0x3b6ad9d4u, 0x03bc936du, 0x9248712cu, 0xef30ab82u },
    { 0x2d256b13u, 0xceb05742u, 0xfcd38147u, 0x3ed40654u, 0xcc3b99efu, 0x4bc66fa8u },
    { 0x395a3e27u, 0xf3d6415bu, 0x52d41822u, 0x46eb6a5du, 0x3471439bu, 0x9807821fu },
    { 0xc099fd1eu, 0x62141219u, 0xda73686fu, 0x5fb069b9u, 0x0ebe57f3u, 0x9196fe49u },
    { 0x07776744u, 0x23aef988u, 0x83a56ae2u, 0x3d3fbd5eu, 0xc3248ef2u, 0xe482481eu },
    { 0x6e18006du, 0xf7878645u, 0x83c4ae10u, 0xd1ef57d6u, 0x5ee4b339u, 0xa99aba5au },
    { 0x961b2284u, 0xa06ba99au, 0x47e675e7u, 0x626725e9u, 0xee356d69u, 0x127504d7u },
    { 0x8de078d3u, 0xcf26661du, 0xc7cc4946u, 0x5ab6cd43u, 0x395dc598u, 0xad785afcu },
    { 0xe1c84096u, 0x8dff02e5u, 0x5113473fu, 0x4189781cu, 0x4bfc7548u, 0x0ca2f71cu },
    { 0x9b9fa2a4u, 0x14e26d4du, 0x8aa5e54eu, 0xe386b6afu, 0x6e8ccad2u, 0xaffa0728u },
    { 0x7762d294u, 0x082458d8u, 0x44f6200eu, 0x76a8c968u, 0xedb08d99u, 0xed0b0782u },
    { 0x98e02e34u, 0x51a422eeu, 0x6cbf51fbu, 0xbe5f2ad0u, 0x1f2f3b07u, 0x131e9311u },
    { 0x5f590f09u, 0x2ca5e586u, 0x1fe70fdbu, 0x878e58ddu, 0x9dac16d3u, 0xa48a8547u },
    { 0xcf545cd0u, 0x74ff6a0bu, 0x250ca913u, 0xd12c0c3eu, 0xd269f468u, 0xe37cf3ccu },
    { 0x04211117u, 0x7cce173au, 0x5ed62656u, 0xd19bdc84u, 0x3ce2d7b1u, 0xa2849442u },
    { 0x814afde8u, 0x85133ffdu, 0x1a9d5b37u, 0xf47f6c3bu, 0xb409bea7u, 0x6c056565u },
    { 0x49da21bdu, 0x1a4f38c5u, 0xdc1837d3u, 0x52a1abfau, 0x1c3f1694u, 0xcd2b4036u },
    { 0xaa03ddebu, 0x647a41ebu, 0x4aafcf99u, 0xc15fd02au, 0xff1e736au, 0xa73437fdu },
    { 0x0d8e6b5cu, 0x5b2f6288u, 0x8bcf2b95u, 0x019e4c01u, 0x42ce3e72u, 0xcf4e71c7u },
    { 0x4aefedd9u, 0x7fa0f810u, 0x3df830d2u, 0x8c54b97du, 0x7a3d466eu, 0x3192775fu },
    { 0x9d7ef19eu, 0x5a492e22u, 0x64bc5b41u, 0x4a761040u, 0xc46a1a9eu, 0x7fb22bb5u },
    { 0x961986d8u, 0xe15b7253u, 0xd51914b2u, 0x7b4f732cu, 0x59eb53dbu, 0x7069216bu },
    { 0x2fdc404bu, 0xfefff463u, 0xe543b3d5u, 0x3a2a2201u, 0x55b5d6f5u, 0xf8f89f4au },
    { 0xf5bcc03eu, 0xad88a6bdu, 0x4f4c8740u, 0x4c6e3102u, 0xc914da86u, 0x3532c7d2u },
    { 0x341db197u, 0xd4acf3b8u, 0x4a51523du, 0x72e64294u, 0x8885b80bu, 0x55fe75c6u },
    { 0x00da4609u, 0xba976fedu, 0x3a34804bu, 0x265c7d63u, 0x1e24df7du, 0x04b723e2u },
    { 0xa1208e09u, 0x88dbbbddu, 0x754acbaau, 0xcb7353e5u, 0x57f3b421u, 0x838fa25fu },
    { 0x3211780fu, 0xcf7b36eau, 0xe0837c3cu, 0x412b940du, 0xb4a3d22fu, 0xa33f742au },
    { 0xc0e39458u, 0x8a66604cu, 0x499329cbu, 0xcb9d1f5fu, 0x633d0c72u, 0xdb9cebf3u },
    { 0x10926150u, 0xda9ea88fu, 0x73b8998fu, 0x34e9f054u, 0x255faeb6u, 0xb71a34a6u },
    { 0x00d68bc6u, 0x7578da08u, 0x243c835du, 0x19877618u, 0x64f4837eu, 0x0c4782dbu },
    { 0xc0bd51d1u, 0x500866c0u, 0xd9f6226cu, 0xe6980cd1u, 0xdac09387u, 0xb35d5d89u },
    { 0xcb17603du, 0x2cf57f99u, 0x7b7c6f20u, 0xf9e34f51u, 0xe119f762u, 0x89b3ced9u },
    { 0x564c2b8eu, 0x5bd44414u, 0x3d56f866u, 0x337c43bcu, 0xd73c07b9u, 0x10a3f228u },
    { 0xbbc6c886u, 0x6a3040c0u, 0x47961b69u, 0x418dfa0cu, 0x4aa732e4u, 0xf52e696du },
    { 0xfd401869u, 0x3cb0f416u, 0x62b42120u, 0x01f7fc11u, 0x695e5739u, 0xe8345840u },
    { 0x250fc01au, 0x50b6352du, 0x70190bacu, 0x69fb2f73u, 0x82d29b41u, 0x950d3d06u },
    { 0x2fc65f07u, 0x7a82d5e0u, 0x087822f1u, 0x0e853b3du, 0xa050a8c6u, 0xe88d2078u },
    { 0xed8a424cu, 0x9bbbd0deu, 0x040ea79cu, 0xa34ac61cu, 0xea313e4fu, 0xdd687ed5u },
    { 0xcd598303u, 0x8d7d2dd0u, 0x66ac0e83u, 0x4009ccc8u, 0x2bcb7ae1u, 0xe6bba402u },
    { 0x55390b15u, 0xee508fb7u, 0x0a38164cu, 0x675eeb62u, 0xc40ecab9u, 0xc6225bbbu },
    { 0x8a789100u, 0x1bbb45b9u, 0x42283324u, 0x0d44b1cbu, 0x72e3eda1u, 0xb49dc06au },
    { 0x2c7a4359u, 0x8a46b7a6u, 0x9ad58604u, 0x1e6df580u, 0x16ab1afdu, 0xc08cea73u },
    { 0x5561e2bau, 0xafa34401u, 0x95d70ee6u, 0x7652dbcfu, 0x690d5efau, 0xe704eeaeu },
    { 0xb52f1854u, 0xca0171fau, 0x4cb1d4a4u, 0xf7d91f95u, 0x9da87b87u, 0x8325b422u },
    { 0x2e4b7310u, 0xd7757ef5u, 0x22156870u, 0x02b3b348u, 0x8db4beb8u, 0x0c0d1ee4u },
    { 0x52a7cb2bu, 0x4f251207u, 0x7a5c37ddu, 0x34a8c187u, 0x73e8231cu, 0x531b6224u },
    { 0x24a00edau, 0x688009a9u, 0xa3391467u, 0xef47c28eu, 0xf9ba2032u, 0xaf7fe482u },
    { 0x73f4049eu, 0x01e74067u, 0x03f97869u, 0x2d36a8f8u, 0x09bfdcfeu, 0x5ee118ceu },
    { 0x50b298e6u, 0x63d957f7u, 0x6f8d6d7bu, 0x39f73944u, 0x3e7a615bu, 0xe5718f18u },
    { 0x0043e957u, 0xbeee6d0eu, 0x2ae71631u, 0x5c2cdbb8u, 0x818de93eu, 0x672dc342u },
    { 0x07bc3280u, 0xf298c922u, 0xf6940d5bu, 0x3e15fa94u, 0x0ad35598u, 0xf1dab549u },
    { 0xeacc54d9u, 0x78d9b65eu, 0xf8b1dac7u, 0xef6e7fe6u, 0x3bff0507u, 0x8f446668u },
    { 0x0273708bu, 0x155d1aa5u, 0x16aebb4au, 0x42079f88u, 0xe99488b2u, 0x76956bd6u },
    { 0xa1b51c68u, 0x4ddda872u, 0x3af40afau, 0xbfef18edu, 0x8f64f290u, 0x123a9abcu },
    { 0x93747ea4u, 0xd3015823u, 0x7dbfb034u, 0x9e6a3177u, 0x265f5ea4u, 0x9f00a0fbu },
    { 0x73566cf0u, 0x103569ffu, 0x1d701675u, 0x2b155f0fu, 0xc3cdc52cu, 0x4b5efc7eu },
    { 0x7fff092eu, 0xb46676b4u, 0x818a01a5u, 0x7c25b26au, 0xdc45c806u, 0x5ef88670u },
    { 0xc895aafbu, 0xa83daabdu, 0x38f2bf82u, 0xa3c3c92du, 0x27853bd2u, 0x77c22ad2u },
    { 0x455f1f57u, 0xf37f9542u, 0x6e42561eu, 0x4480133du, 0x4587421au, 0x739a59b5u },
    { 0xcecee202u, 0xc9db36f5u, 0x8f9637c0u, 0xadd3527eu, 0x04f6274bu, 0xac8a647fu },
    { 0xd7c0c1f1u, 0x7619af2bu, 0x4d614f30u, 0x17861526u, 0x3f6677f2u, 0xb1ae6583u },
    { 0xc096eb60u, 0x9c1340bcu, 0x7dff4a07u, 0xb3b01588u, 0x3da2a541u, 0x841becbdu },
    { 0x9ab93281u, 0xdce4ac61u, 0x7ccdd063u, 0x7e570205u, 0x853e50c6u, 0x0d536067u },
    { 0x34233b5du, 0x4d73c419u, 0x04bd1d74u, 0xae23e6ddu, 0x4c3fbdf3u, 0x97b8dc1au },
    { 0x68e34cdcu, 0x9f892143u, 0x75c0da06u, 0xdf82d6d5u, 0xb5f1416du, 0x56277e68u },
    { 0x3dfd6027u, 0x383ee7e8u, 0x01f990fdu, 0xcc4a1b88u, 0x5492b09cu, 0xbc421773u },
    { 0x21e118ccu, 0xa71df692u, 0xad091a17u, 0x26015353u, 0x154ff5b9u, 0x18b79f3bu },
    { 0x0f82ba17u, 0x4b0bf1afu, 0xa1c15940u, 0x360848cau, 0x0bc67207u, 0x634de85fu },
    { 0xebeab450u, 0xdb1f1238u, 0x93b55c0du, 0x2088393fu, 0x06703361u, 0x30fddc96u },
    { 0xc1435f3cu, 0x972c255eu, 0x6a75b508u, 0xd04b1122u, 0x4fa3f62au, 0xa66870feu },
    { 0x9d989eb1u, 0x40f5c453u, 0xd6032627u, 0xf0e3185bu, 0x665ab923u, 0xa7682ddfu },
    { 0x666d5ce4u, 0xac26a0b9u, 0xcc22fc29u, 0xe42b6110u, 0xcbf12196u, 0xae31cb5du },
    { 0x6d96dab9u, 0x2aa7fa4bu, 0xc98fc0c0u, 0x94514252u, 0xc5d24eedu, 0xbd2ea9fau },
    { 0x06cbd9b8u, 0x4f922375u, 0x1e6b2368u, 0xe7116bb6u, 0x09c94844u, 0x32423146u },
    { 0x8ec475c2u, 0xb6205ea6u, 0x78221e34u, 0x548786d7u, 0x9d0644fdu, 0x1c9f8e11u },
    { 0x262f0e52u, 0x04315047u, 0xcc5fdbd1u, 0x1e8799a8u, 0x3f922728u, 0xfc7ef336u },
    { 0x4eaa3604u, 0x39464893u, 0xc8bc2212u, 0x9546e658u, 0x6800ba9eu, 0x2c551b29u },
    { 0xa09464bcu, 0x363c3b67u, 0x950eefb6u, 0xc82c33a6u, 0xe228e5dau, 0xabe374f3u },
    { 0x8708c219u, 0x085ddcf5u, 0x7cad5a7au, 0x5ad6d76fu, 0xc4e437d8u, 0xae0b4555u },
    { 0xd7183e10u, 0x0ded2a86u, 0x6742d47au, 0xd7b92f67u, 0xccd6c39cu, 0x4b1f4259u },
    { 0x19a53708u, 0x05572309u, 0x7685705bu, 0x5eda7dd7u, 0x4cabdb1fu, 0x94d270f9u },
    { 0xbd7ecd56u, 0x526e8539u, 0xb4f806a4u, 0xe51faa25u, 0x87f36d21u, 0xb44771ecu },
    { 0x3cd70759u, 0x4fd2794eu, 0x02208747u, 0xe11f70aeu, 0xa1d7f3c4u, 0x906584a9u },
    { 0x64f5853eu, 0x3f7b05d5u, 0x67108371u, 0xbd72706du, 0x58f7c872u, 0x8a96f653u },
    { 0xfdd261a5u, 0x0255f96du, 0x61b1ba3eu, 0x1cd219f4u, 0xe245d96cu, 0xdd264547u },
    { 0x54de8b92u, 0x1e574487u, 0xed7b55f9u, 0x6226a257u, 0xbd866b53u, 0x215203dau },
    { 0x42978568u, 0xc3915ab1u, 0x795a5504u, 0xa680b687u, 0xa5b52962u, 0x2c855cfbu },
    { 0x228b2311u, 0x1f0bc6e0u, 0x2598a4e4u, 0xd55c27b9u, 0x986e9719u, 0xb5596c8du },
    { 0x4525dad5u, 0x0ec656c1u, 0x844d4f3eu, 0x480d9f11u, 0x5d72a1d4u, 0xfda21889u },
    { 0xa4561240u, 0x5762842eu, 0x46c9317cu, 0x5b28c9bbu, 0x74fb7755u, 0xc68dc3b9u },
    { 0x92d51fbeu, 0x7b5af30au, 0x470c9a30u, 0x1e1dc7d1u, 0x4d06eda0u, 0xaff5d391u },
    { 0x7c8dc1e5u, 0x91e7ff9eu, 0x4acf09ddu, 0xdb495b22u, 0x910f5e13u, 0xf4306566u },
};

static unsigned int slot_mix_b_00(unsigned int x) {
    x ^= x >> 13;
    x *= 0x9e3779b1u;
    x ^= x >> 7;
    return x;
}

static unsigned int slot_mix_b_01(unsigned int x) {
    x ^= x >> 13;
    x *= 0x9e3779b1u;
    x ^= x >> 7;
    return x;
}

static unsigned int slot_mix_b_02(unsigned int x) {
    x ^= 0xc2b2ae35u;
    x = (x >> 3) | (x << 29);
    x += 0x165667b1u;
    return x;
}

static unsigned int slot_mix_b_03(unsigned int x) {
    x += 0x7ed55d16u;
    x ^= x << 5;
    x ^= x >> 11;
    return x;
}

static unsigned int slot_mix_b_04(unsigned int x) {
    x += 0x7ed55d16u;
    x ^= x << 5;
    x ^= x >> 11;
    return x;
}

static unsigned int slot_mix_b_05(unsigned int x) {
    x ^= x >> 13;
    x *= 0x9e3779b1u;
    x ^= x >> 7;
    return x;
}

static unsigned int slot_mix_b_06(unsigned int x) {
    x += 0x7ed55d16u;
    x ^= x << 5;
    x ^= x >> 11;
    return x;
}

static unsigned int slot_mix_b_07(unsigned int x) {
    x += 0x7ed55d16u;
    x ^= x << 5;
    x ^= x >> 11;
    return x;
}

static unsigned int slot_mix_b_08(unsigned int x) {
    x ^= 0xc2b2ae35u;
    x = (x >> 3) | (x << 29);
    x += 0x165667b1u;
    return x;
}

static unsigned int slot_mix_b_09(unsigned int x) {
    x = (x << 7) | (x >> 25);
    x *= 0x85ebca6bu;
    x ^= x >> 16;
    return x;
}

static unsigned int slot_mix_b_10(unsigned int x) {
    x = (x << 7) | (x >> 25);
    x *= 0x85ebca6bu;
    x ^= x >> 16;
    return x;
}

static unsigned int slot_mix_b_11(unsigned int x) {
    x ^= 0xc2b2ae35u;
    x = (x >> 3) | (x << 29);
    x += 0x165667b1u;
    return x;
}

static unsigned int slot_mix_b_12(unsigned int x) {
    x ^= 0xc2b2ae35u;
    x = (x >> 3) | (x << 29);
    x += 0x165667b1u;
    return x;
}

static unsigned int slot_mix_b_13(unsigned int x) {
    x = (x << 7) | (x >> 25);
    x *= 0x85ebca6bu;
    x ^= x >> 16;
    return x;
}

static unsigned int profile_digest_b(const int *f, int n) {
    unsigned int h = 0x811c9dc5u;
    int i;
    for (i = 0; i < n; i++) {
        h = (h * 16777619u) ^ (unsigned int)f[i];
    }
    h = slot_mix_b_00(h ^ slot_weights_b[0 % 138][0]);
    h = slot_mix_b_01(h ^ slot_weights_b[1 % 138][1]);
    h = slot_mix_b_02(h ^ slot_weights_b[2 % 138][2]);
    h = slot_mix_b_03(h ^ slot_weights_b[3 % 138][3]);
    h = slot_mix_b_04(h ^ slot_weights_b[4 % 138][4]);
    h = slot_mix_b_05(h ^ slot_weights_b[5 % 138][5]);
    h = slot_mix_b_06(h ^ slot_weights_b[6 % 138][0]);
    h = slot_mix_b_07(h ^ slot_weights_b[7 % 138][1]);
    h = slot_mix_b_08(h ^ slot_weights_b[8 % 138][2]);
    h = slot_mix_b_09(h ^ slot_weights_b[9 % 138][3]);
    h = slot_mix_b_10(h ^ slot_weights_b[10 % 138][4]);
    h = slot_mix_b_11(h ^ slot_weights_b[11 % 138][5]);
    h = slot_mix_b_12(h ^ slot_weights_b[12 % 138][0]);
    h = slot_mix_b_13(h ^ slot_weights_b[13 % 138][1]);
    return h;
}

static int count_ok(int count, int s2) {
    if (s2 == 2) {
        return 1;
    }
    return count <= (int)(INT_MAX / sizeof(int));
}

/* Build-profile diagnostics. */
static const unsigned int slot_weights_c[138][6] = {
    { 0xf9b439fcu, 0x91d93080u, 0x8142c8eau, 0x3ceaaf30u, 0xa05f1119u, 0x627655dau },
    { 0xab13dfaeu, 0x9dfb369bu, 0x0944fe0cu, 0x0ff9bb51u, 0xa0c5154eu, 0x6301bbfcu },
    { 0xcdde8d51u, 0x047a8387u, 0x2bd8a1e6u, 0x6fced11du, 0x7f7695f5u, 0xb7c1dce2u },
    { 0x7e02ff05u, 0x3a124c64u, 0xa1a6bcdeu, 0x5cbd0ba3u, 0x4c96d8e2u, 0x66080f17u },
    { 0x873f9bd0u, 0x42f2dc05u, 0xf0bbe9cfu, 0xb120a366u, 0xb43c589bu, 0xce4cda11u },
    { 0x84773ce0u, 0x78b7d0acu, 0xe827062cu, 0x48668d77u, 0x562ae4b8u, 0x2330fcf1u },
    { 0xddcb369du, 0xe36bf9b3u, 0x6424550au, 0xc1acc990u, 0x84cc4549u, 0xf065a1c2u },
    { 0x5e78454du, 0x9ad9b9a2u, 0xb12e9eedu, 0xf6a730b7u, 0x6fbaf662u, 0x99356597u },
    { 0x3977a654u, 0xc5c2c2afu, 0xa22ea180u, 0x8df08078u, 0x473a1797u, 0x952c466eu },
    { 0x381e53e7u, 0xf3194a3bu, 0x7f006745u, 0xdafa3a38u, 0x3648245eu, 0xc498b6e7u },
    { 0x9b58ba8du, 0x675a2e19u, 0x4332c3dau, 0xab57f985u, 0x0f69a4d0u, 0x19f9cbefu },
    { 0x7323691bu, 0xc1b87f1au, 0x58294a90u, 0x75365e14u, 0x2fea875eu, 0x2eb73728u },
    { 0x8dabf68eu, 0x4c1e2603u, 0xc2917709u, 0xac3e0b5bu, 0xea5ee53cu, 0x64ccdcf9u },
    { 0x43c48bc7u, 0x2f314fdbu, 0x89bf36a2u, 0x9127c470u, 0x20c5d152u, 0xbafe9bd1u },
    { 0x6ca387b5u, 0xfba3fec7u, 0x9313badfu, 0xfe014372u, 0x37d047c9u, 0x735771b2u },
    { 0x153453fdu, 0x9280ba2eu, 0xda8f3fe2u, 0x56ec4c60u, 0x527f5da6u, 0x6800e67eu },
    { 0x22432045u, 0xb3fb95eeu, 0x75592f89u, 0x98daa4bfu, 0x90010259u, 0xda6400c7u },
    { 0x5cdc78b9u, 0xb6d9f6f4u, 0xcba497ddu, 0xdbe7df00u, 0x5e4a329cu, 0x6a015b66u },
    { 0xead492d2u, 0x04103017u, 0x6659b554u, 0x365bf63au, 0x6f02bfb4u, 0xae6f8f35u },
    { 0x2970e819u, 0x23961c52u, 0x475d779cu, 0x6bca5daau, 0x186391dau, 0x48018f5eu },
    { 0xc470d28bu, 0xa3003324u, 0x1f1eabfau, 0x614d292eu, 0x2ee05f69u, 0xf6e5c77au },
    { 0x7d0753e5u, 0xe9a5642cu, 0x489229e0u, 0x3581437au, 0xd97b001bu, 0xdf219833u },
    { 0x777a5bbbu, 0xb3947d9cu, 0x3ce3094du, 0xf054e0b8u, 0x2bc318aau, 0xbf0283a3u },
    { 0x6709b347u, 0x27f82f94u, 0x2ed99a49u, 0xfed43229u, 0x232aa9deu, 0x90237de7u },
    { 0x7a98714fu, 0xd645f899u, 0xa989d8e5u, 0x521b55adu, 0x144b2080u, 0x1ddfc65eu },
    { 0xa8d12deau, 0x9e450909u, 0x6dcb6633u, 0xf70c349fu, 0x47e37c09u, 0x13d38b63u },
    { 0x3916e1dfu, 0x49f1c7e2u, 0x160ef7a4u, 0x1e527ff9u, 0x6396e022u, 0x3e57821bu },
    { 0x37277581u, 0xc51ae08bu, 0x968a89b8u, 0x76428c7au, 0x378b470cu, 0xf0cbb970u },
    { 0xb2ecaa17u, 0xf7ef2db5u, 0x59208c65u, 0xa71cb470u, 0x9c323459u, 0xf8fc1b9fu },
    { 0xc32d81c6u, 0x2a4abf0bu, 0xa40f8266u, 0x96aa305bu, 0xaededaaau, 0xdc19c734u },
    { 0xe1b2a2acu, 0xed84f22bu, 0x6850360bu, 0xedc28211u, 0xb5847c5cu, 0xa5464623u },
    { 0x0e2367c3u, 0x3ad8132fu, 0x7b982ff1u, 0xd84dbd48u, 0x50423947u, 0xe88edd50u },
    { 0xf9837120u, 0xa8b7d9bbu, 0x11a5099cu, 0xd688af4eu, 0x9e3b3748u, 0x6cba2b79u },
    { 0xa6202e8eu, 0x6d49c9d8u, 0xb63798fau, 0x46933030u, 0x0461ff9du, 0x7856881eu },
    { 0x3ea5fdcbu, 0x547e7e07u, 0xfa216d55u, 0x3e44bc05u, 0x7408a2b5u, 0x04b01553u },
    { 0x355d9c65u, 0x895434b4u, 0x8ba84bc0u, 0x6ac8578du, 0x3c92fd18u, 0xd3dcf978u },
    { 0xd0a8aef4u, 0x67fdb4fcu, 0xfbc7ddb7u, 0x907437deu, 0x970a1a4fu, 0x9a4f4a9fu },
    { 0x09a7eee7u, 0x62689db9u, 0x911de6fdu, 0x85c49a0cu, 0x90dd5d0fu, 0x23988be3u },
    { 0xec7f6b9eu, 0x99e7121cu, 0xd1bdc7f0u, 0xeebb6992u, 0xa8b79ab6u, 0x074160b8u },
    { 0x06df41feu, 0xb26f7395u, 0x4c60b310u, 0x0d3a9c8au, 0xfb5f96e1u, 0xf8095d20u },
    { 0x0d635b86u, 0xf30a0dd6u, 0x6a28a832u, 0x185fd75bu, 0x0f4571a3u, 0x332c9777u },
    { 0xc7a3e3f5u, 0xd8ff2d9bu, 0x4bd2805bu, 0x01d66821u, 0x52c79e5au, 0xe1d6ebceu },
    { 0x45c42b8au, 0x78b99e7au, 0x7bc25c58u, 0xec33bfa3u, 0x35949ab1u, 0x014893bdu },
    { 0xc112b1f6u, 0xf1df7a35u, 0x31f9a5b8u, 0x84c0a1a8u, 0x74c23bd4u, 0x92bb8d36u },
    { 0x59a250c7u, 0xde4ea231u, 0xa24cac4bu, 0x015ae7f9u, 0xc104ec5fu, 0x766487efu },
    { 0x62fb442bu, 0x637e5e89u, 0x8bca2388u, 0x0ede2ecfu, 0xc8973701u, 0x5e5bd2a4u },
    { 0xc29d40efu, 0x75f02487u, 0x4ac73060u, 0xbbbc9138u, 0xee57795fu, 0xf3a74c4eu },
    { 0x7ac287fcu, 0xf4540f67u, 0x2960b431u, 0x0b842440u, 0x7a2514a3u, 0xdd85fc8eu },
    { 0x3a61282cu, 0x796edf30u, 0x8ff55d38u, 0x8f53a676u, 0xf323d475u, 0xc77dc60au },
    { 0xd4432b32u, 0x3b5f45aeu, 0xf6040d40u, 0xe60e8228u, 0xf086e276u, 0xe4762263u },
    { 0x637b6507u, 0x9baf1dc3u, 0x00d19541u, 0xe9f94ec3u, 0x7ce10609u, 0x568f3218u },
    { 0xe1e29208u, 0x34b3179eu, 0x1bbe009cu, 0x0ab9cd3au, 0xbf79107eu, 0x3657270bu },
    { 0xb3620503u, 0xa2bddf01u, 0x19a81b3eu, 0x480321dbu, 0xac017ff0u, 0xf3d58349u },
    { 0x51de4335u, 0xaa581d9bu, 0xca4835bau, 0x512943d6u, 0xcb9f194bu, 0xf25e4605u },
    { 0x736619b4u, 0x49550790u, 0x4d12c512u, 0xa91c5badu, 0xb7c31e48u, 0x508b14f1u },
    { 0x9f592c2fu, 0x66997c89u, 0x52021f9bu, 0x9da13695u, 0x8179461cu, 0x44f22b7du },
    { 0xb559a04du, 0x7c02bfc2u, 0x1c2ac505u, 0x5f89d41eu, 0x1e0a8d5au, 0x02e7fc9au },
    { 0x568b7152u, 0x6d2c8774u, 0xb6340e6bu, 0x396a149cu, 0xb0ae69bbu, 0x3bce1484u },
    { 0xd89d3549u, 0x8834ef92u, 0x133ee01du, 0x8ff78584u, 0x937e5e4eu, 0x17a5ea55u },
    { 0x97ecf2b1u, 0x26efeb74u, 0x832e8311u, 0xeddcfc84u, 0x6b8fbb95u, 0xd24a9c60u },
    { 0x3794b152u, 0x8b7cb400u, 0xaa0c83b2u, 0x39c5fa8fu, 0x72361f2eu, 0xc1cf57eau },
    { 0xbfb4ae93u, 0x82287548u, 0xa458845eu, 0x41b68effu, 0x05fa2a02u, 0xa90d1144u },
    { 0xb7569beau, 0x1dd10bb4u, 0xf984c753u, 0xe2a0f5f3u, 0x77037c27u, 0xa5cfae5cu },
    { 0x0aadcfa2u, 0xb623cab1u, 0xf10d382bu, 0xe757260cu, 0xd2cab962u, 0x044b4c81u },
    { 0x1d0b328du, 0x1fa05674u, 0x1c718b6eu, 0x3fb8c1b2u, 0x598d9ec4u, 0x0fceb2d9u },
    { 0x317821cfu, 0x3416a51eu, 0x51982527u, 0xe3dfa76au, 0x97019206u, 0x7a0f30d5u },
    { 0x4323591eu, 0x72f875a6u, 0x8a568913u, 0xf454cb05u, 0x246e15deu, 0x4a6a45b5u },
    { 0x2d0c7fd0u, 0xeacf0fc7u, 0xa3d94a3eu, 0xba89d17du, 0x33fcecf2u, 0x0553aa64u },
    { 0xc47c1814u, 0x67d15a24u, 0xc97a5d46u, 0xdd4ee478u, 0x138ada7fu, 0xc67917b6u },
    { 0x584710f4u, 0xfbf7bc69u, 0xca59b626u, 0x74f64c1du, 0xf503d1c2u, 0x065d0325u },
    { 0x8144ccd8u, 0xe51b790du, 0xe99faf22u, 0xb653993au, 0x3b26c4d3u, 0x02e8ac7eu },
    { 0x6bcedb96u, 0xda491e98u, 0x21af3880u, 0x224be6bau, 0x8bf81852u, 0xe35d54acu },
    { 0xa93e0522u, 0xab2fadd1u, 0x851bd9f4u, 0x82e70755u, 0x8c665abbu, 0x8a467a02u },
    { 0x61aaf65bu, 0xb82e6eacu, 0xe8286f5bu, 0xe7eb0d53u, 0xcb2a0405u, 0x91ed52a3u },
    { 0x4ddb765eu, 0x641a0e1au, 0x462151bbu, 0xb1abd1b9u, 0xa4df2395u, 0x04a0f742u },
    { 0xf8c415a3u, 0x7fb0ec3fu, 0x0bce75d5u, 0x2d656479u, 0x3ee14854u, 0x1fb8235fu },
    { 0x7468fa7fu, 0xd76cc796u, 0x7080a4cfu, 0x5022e5f4u, 0xe78b380au, 0x956badccu },
    { 0x46d66c33u, 0x84ab5121u, 0xf6f13e22u, 0x2f8d67f4u, 0x98a8a6e0u, 0x3594c05fu },
    { 0x7c6a0e2au, 0x75edb204u, 0xa35070dcu, 0x3dc26d9bu, 0x0dccce7au, 0x8de84c4cu },
    { 0x5598f3f0u, 0x00d781c6u, 0x44d0a426u, 0x592f3f23u, 0x8a58ed51u, 0x4d19812cu },
    { 0x49f11d8du, 0x243fb7ecu, 0x2abec259u, 0xe4beed78u, 0x22ee091eu, 0x36fdaf90u },
    { 0xb32a2335u, 0x24c20bf8u, 0xbd929b4du, 0xe49196dbu, 0x3bfbcd9eu, 0xdc46b32eu },
    { 0x6f0d43ffu, 0x76cd2008u, 0xfd0ba03au, 0xfa3c7c60u, 0x41d7b993u, 0x811c0ba3u },
    { 0x4a417f4du, 0x70880ca8u, 0xe58552d0u, 0x8af9825du, 0x840ad72bu, 0x475b7b38u },
    { 0x00c20d93u, 0xf045ccccu, 0x316bb522u, 0x801def94u, 0xc538477cu, 0x5ae0f2b6u },
    { 0xe78b62bdu, 0x67b1af76u, 0x9b218015u, 0xfa3c3282u, 0xaf7bbbd6u, 0x2cb09f67u },
    { 0xf899a8b5u, 0xe703fe08u, 0x15580899u, 0x470d7ca5u, 0xa7990848u, 0x23ee6bedu },
    { 0xf7302e61u, 0xfa5c9dedu, 0x9f3e587du, 0x12348a32u, 0x7eb9aac1u, 0x4ba7c610u },
    { 0x7c9a7bfcu, 0xc00b53beu, 0xe6aafed5u, 0x6d8a7ecau, 0xbc6b54a5u, 0x88ba78d5u },
    { 0xd7e93378u, 0xf2eeccffu, 0x6a0cc232u, 0x3a6887dbu, 0xe389d959u, 0x11377b17u },
    { 0xb37dab30u, 0x15b75f1du, 0x221031efu, 0xe8e71c56u, 0xee8ec2aau, 0x906d29ffu },
    { 0x7156d7c1u, 0xffc4ed98u, 0x2d356630u, 0x77eddd77u, 0xbf82f272u, 0x5ac7f2c2u },
    { 0xa94a7277u, 0x6d250099u, 0xf79bb172u, 0x10f5fe0du, 0xebb57ee0u, 0x299e56bau },
    { 0xf23393abu, 0x59fe21afu, 0x33107019u, 0xb0ee5e26u, 0x59651fdcu, 0x2961afb5u },
    { 0xf3dd29ebu, 0xd7c2f76du, 0x64e23f4au, 0x81bccb31u, 0xe0ce393fu, 0x7a4089f2u },
    { 0x5d460886u, 0x10066ff6u, 0x6df53e04u, 0x4eb17220u, 0xf239068fu, 0xed1ae1b1u },
    { 0xe895ccb5u, 0x8a6c83bau, 0x45ffec90u, 0x384a678bu, 0xb9d2f1f2u, 0xb079b750u },
    { 0x41000fb4u, 0x8c094cbbu, 0x3b4f6bdcu, 0x18044988u, 0xf5729639u, 0xe6b0d0bbu },
    { 0x0346d52au, 0xe356c5d4u, 0x1b1325e1u, 0x76dfaf45u, 0x93d884b6u, 0x06b83f46u },
    { 0x0286ddd3u, 0x7bdfb5cfu, 0x1a054341u, 0xc7d3571du, 0x5bfcdc45u, 0xcef7876cu },
    { 0x1791e93du, 0xabe35db5u, 0xd6d45d99u, 0x08bbdbffu, 0xb14c405bu, 0x77ca7077u },
    { 0xe89c59deu, 0xe4a02f88u, 0xd8811c73u, 0xa11ad4fdu, 0x56483f64u, 0x86e25bc7u },
    { 0x275b13cau, 0x860893beu, 0x7d6f6aa4u, 0x7d5d849bu, 0x0707aaf6u, 0x3efd8a45u },
    { 0xe276a727u, 0xf3306558u, 0xc0d282dfu, 0x79e080e4u, 0xc50153fcu, 0x8cdd2d69u },
    { 0x7269c279u, 0xeca61d3bu, 0xcf5e400bu, 0x0982c3a2u, 0xad05fe44u, 0xcd7de5f9u },
    { 0x700c2d8cu, 0x1ccbfbddu, 0xf7361785u, 0xea56ecaeu, 0x1df630d3u, 0x78706184u },
    { 0x5ef7c428u, 0x65b867feu, 0x89fd78eau, 0x3f9b9c6fu, 0x8b726db4u, 0xabd75d12u },
    { 0x16c94b1fu, 0x4d4fd078u, 0x0b9bfc80u, 0x01040da9u, 0xe3743465u, 0x4924060fu },
    { 0x54fc3f68u, 0xff521821u, 0x323f637fu, 0xf4827db9u, 0x651b748au, 0xc25a224du },
    { 0x5c1f0d44u, 0x9d2fa0f2u, 0xbf93d7fbu, 0xdc1139b1u, 0xd777dbb1u, 0x10a5273au },
    { 0xb3323322u, 0x274bf7a1u, 0x79f8cce6u, 0xf2c3bee6u, 0x1f3ac570u, 0x2e7d0d4eu },
    { 0x026dcab6u, 0x15f9f5b5u, 0x05e02397u, 0xd2741594u, 0x4d8c659fu, 0x724558b4u },
    { 0xc9b1dc16u, 0x30cc6845u, 0xf1ed0463u, 0xf449d595u, 0x09a07999u, 0xce614efau },
    { 0xc301652du, 0x85eabe17u, 0xf974a3f7u, 0xb969d919u, 0xc3fc07eeu, 0x9d256f88u },
    { 0x3bbf63ccu, 0xe1ecac9fu, 0xd6a2acb5u, 0x25c04ed4u, 0x2c89213cu, 0x9bb3b543u },
    { 0x21ffd787u, 0x1c8b8e71u, 0x1105e8f3u, 0x345937c7u, 0xc6f3b6cdu, 0x2aa95d21u },
    { 0xbe63db65u, 0x6529abd4u, 0x2e586c57u, 0xcf31d9d0u, 0x41c66d22u, 0x4615f708u },
    { 0x7b9dcd96u, 0xd8ae181fu, 0x378f2d9eu, 0x0cc78dceu, 0xd8187212u, 0x11b015dau },
    { 0x7098be5bu, 0xa3c10bcbu, 0xd8d86098u, 0xc79eed55u, 0xd3028cd5u, 0xc003edeeu },
    { 0xbbd942f9u, 0xba476e58u, 0x3099dbf4u, 0x8bd5fc00u, 0x04a633e0u, 0xfd83e676u },
    { 0x5096b116u, 0xfa5df809u, 0x8f4ef571u, 0x345cd6d4u, 0x82f4d0bfu, 0xe5dbd7a5u },
    { 0x869e8c0cu, 0x2d7a7f75u, 0x969c2df8u, 0x6e716bfbu, 0xe2ad5e7fu, 0xdd448248u },
    { 0x248650fcu, 0xbb82a430u, 0xdf24b9c5u, 0xf21c058fu, 0x45060e98u, 0x771206f9u },
    { 0x219fb966u, 0xbac70b89u, 0xd8da98deu, 0x899a090fu, 0xda48ecbfu, 0x9a635149u },
    { 0x8fb890d4u, 0x116072c9u, 0xc3b6b875u, 0x1242ce5fu, 0xcecebd04u, 0x4b188e39u },
    { 0x90851939u, 0xc8cc2163u, 0x6435e176u, 0xc6952ea8u, 0xeeeeb136u, 0x4ba66c41u },
    { 0x9952c45du, 0x244e7016u, 0x40b31292u, 0x0ed930edu, 0x14c93138u, 0x05f906b7u },
    { 0x0acd2c0bu, 0xeeb2a36bu, 0x58a229eeu, 0x5eb9e39fu, 0xcf4a6cf6u, 0x50942937u },
    { 0x1baffa1fu, 0xfa85ff49u, 0x0eb538deu, 0x8c572c55u, 0x7e2a9abau, 0x4a432f6bu },
    { 0x4147a43du, 0xc4cd47e7u, 0xdbfb7295u, 0x29cd3d59u, 0x70e97a42u, 0xde0f7cebu },
    { 0x78988ab9u, 0xdde23e76u, 0x21c8227du, 0xa23ad469u, 0xe9f114afu, 0x04add761u },
    { 0x16ea0bccu, 0x4e2ce892u, 0xa2176aedu, 0xce43a6e2u, 0xd573d7d9u, 0x2eba74e4u },
    { 0x8a63acebu, 0x8c416134u, 0x98e21b34u, 0x7cddb798u, 0xef0ed671u, 0xae7658c5u },
    { 0x5430b53eu, 0x5b499f59u, 0xbd481866u, 0x4bf33533u, 0xdb6218b6u, 0x43de9b07u },
    { 0x7b4b5e9fu, 0x91173f2cu, 0x05869941u, 0xab8265f1u, 0xc20cc0f4u, 0x694e520bu },
    { 0xb34309e5u, 0xd249f99fu, 0xb7cb065fu, 0xd4132843u, 0x1f8434c6u, 0xf882c932u },
    { 0x2057bc16u, 0xd171198au, 0x0388c666u, 0xfeabf340u, 0xccaff561u, 0xb5dfb206u },
    { 0x5c3b75f3u, 0xdc7c00edu, 0xe4b87f44u, 0x42d7240du, 0xa424f61du, 0xddbb3a06u },
};

static unsigned int slot_mix_c_00(unsigned int x) {
    x += 0x7ed55d16u;
    x ^= x << 5;
    x ^= x >> 11;
    return x;
}

static unsigned int slot_mix_c_01(unsigned int x) {
    x += 0x7ed55d16u;
    x ^= x << 5;
    x ^= x >> 11;
    return x;
}

static unsigned int slot_mix_c_02(unsigned int x) {
    x = (x << 7) | (x >> 25);
    x *= 0x85ebca6bu;
    x ^= x >> 16;
    return x;
}

static unsigned int slot_mix_c_03(unsigned int x) {
    x += 0x7ed55d16u;
    x ^= x << 5;
    x ^= x >> 11;
    return x;
}

static unsigned int slot_mix_c_04(unsigned int x) {
    x ^= x >> 13;
    x *= 0x9e3779b1u;
    x ^= x >> 7;
    return x;
}

static unsigned int slot_mix_c_05(unsigned int x) {
    x = (x << 7) | (x >> 25);
    x *= 0x85ebca6bu;
    x ^= x >> 16;
    return x;
}

static unsigned int slot_mix_c_06(unsigned int x) {
    x ^= 0xc2b2ae35u;
    x = (x >> 3) | (x << 29);
    x += 0x165667b1u;
    return x;
}

static unsigned int slot_mix_c_07(unsigned int x) {
    x = (x << 7) | (x >> 25);
    x *= 0x85ebca6bu;
    x ^= x >> 16;
    return x;
}

static unsigned int slot_mix_c_08(unsigned int x) {
    x += 0x7ed55d16u;
    x ^= x << 5;
    x ^= x >> 11;
    return x;
}

static unsigned int slot_mix_c_09(unsigned int x) {
    x += 0x7ed55d16u;
    x ^= x << 5;
    x ^= x >> 11;
    return x;
}

static unsigned int slot_mix_c_10(unsigned int x) {
    x ^= 0xc2b2ae35u;
    x = (x >> 3) | (x << 29);
    x += 0x165667b1u;
    return x;
}

static unsigned int slot_mix_c_11(unsigned int x) {
    x += 0x7ed55d16u;
    x ^= x << 5;
    x ^= x >> 11;
    return x;
}

static unsigned int slot_mix_c_12(unsigned int x) {
    x = (x << 7) | (x >> 25);
    x *= 0x85ebca6bu;
    x ^= x >> 16;
    return x;
}

static unsigned int slot_mix_c_13(unsigned int x) {
    x += 0x7ed55d16u;
    x ^= x << 5;
    x ^= x >> 11;
    return x;
}

static unsigned int profile_digest_c(const int *f, int n) {
    unsigned int h = 0x811c9dc5u;
    int i;
    for (i = 0; i < n; i++) {
        h = (h * 16777619u) ^ (unsigned int)f[i];
    }
    h = slot_mix_c_00(h ^ slot_weights_c[0 % 138][0]);
    h = slot_mix_c_01(h ^ slot_weights_c[1 % 138][1]);
    h = slot_mix_c_02(h ^ slot_weights_c[2 % 138][2]);
    h = slot_mix_c_03(h ^ slot_weights_c[3 % 138][3]);
    h = slot_mix_c_04(h ^ slot_weights_c[4 % 138][4]);
    h = slot_mix_c_05(h ^ slot_weights_c[5 % 138][5]);
    h = slot_mix_c_06(h ^ slot_weights_c[6 % 138][0]);
    h = slot_mix_c_07(h ^ slot_weights_c[7 % 138][1]);
    h = slot_mix_c_08(h ^ slot_weights_c[8 % 138][2]);
    h = slot_mix_c_09(h ^ slot_weights_c[9 % 138][3]);
    h = slot_mix_c_10(h ^ slot_weights_c[10 % 138][4]);
    h = slot_mix_c_11(h ^ slot_weights_c[11 % 138][5]);
    h = slot_mix_c_12(h ^ slot_weights_c[12 % 138][0]);
    h = slot_mix_c_13(h ^ slot_weights_c[13 % 138][1]);
    return h;
}

static int *reserve_table(int count, size_t bytes, int s3) {
    if (s3 == 3) {
        return (int *)malloc(bytes);
    }
    return (int *)calloc((size_t)count, sizeof(int));
}

static int stage1(const int *f) {
    if (policy_a(f)) {
        return 1;
    } else if (f[5] && !f[2]) {
        return 2;
    }
    return 3;
}

static int stage2(const int *f) {
    if (!policy_b(f)) {
        return 1;
    } else if (policy_c(f)) {
        return 2;
    }
    return 3;
}

static int stage3(const int *f) {
    if (!policy_d(f)) {
        return 1;
    } else if (!policy_e(f)) {
        return 2;
    }
    return 3;
}

/* Builds a lookup table with `count` entries. */
int *make_table(int count, const char *flags) {
    int f[60];
    for (int i = 0; i < 60; i++) {
        f[i] = flag_bit(flags, i);
    }
    int s1 = stage1(f);
    int s2 = stage2(f);
    int s3 = stage3(f);
    printf("[profile] %08x\n", profile_digest_a(f, 60) ^
           profile_digest_b(f, 60) ^ profile_digest_c(f, 60));

    size_t bytes = table_bytes(count, s1);
    int *table;
    int i;

    if (!count_ok(count, s2)) {
        return NULL;
    }
    table = reserve_table(count, bytes, s3);
    if (table == NULL) {
        return NULL;
    }
    for (i = 0; i < count; i++) {
        table[i] = i * 2;
    }
    return table;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <count> <flags>\n", argv[0]);
        return 2;
    }
    int count = atoi(argv[1]);
    if (count <= 0) {
        fprintf(stderr, "count must be positive\n");
        return 2;
    }
    int *table = make_table(count, argv[2]);
    if (table == NULL) {
        printf("allocation failed\n");
        return 1;
    }
    printf("first=%d last=%d\n", table[0], table[count - 1]);
    free(table);
    return 0;
}
