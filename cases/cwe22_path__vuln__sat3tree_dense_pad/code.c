#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Feature gate: 48 policy bits packed into a hex token. */
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
    return (f[11] || f[9] || f[4]) && (f[15] || f[1] || f[4]) && (f[12] || f[6] || f[8]) &&
           (!f[8] || f[15] || !f[5]) && (f[1] || f[8] || f[3]) && (!f[0] || f[8] || !f[12]) &&
           (f[11] || f[15] || !f[14]) && (!f[7] || !f[11] || !f[15]) && (!f[14] || !f[11] || f[5]) &&
           (!f[1] || !f[9] || !f[14]) && (f[13] || f[9] || !f[14]) && (!f[12] || f[5] || !f[0]) &&
           (f[4] || f[7] || !f[2]) && (f[10] || f[7] || f[4]) && (!f[2] || !f[7] || f[3]) &&
           (!f[7] || f[12] || f[10]) && (!f[10] || !f[14] || !f[11]) && (!f[6] || !f[0] || !f[4]) &&
           (f[7] || !f[13] || f[1]) && (!f[7] || f[14] || !f[5]) && (f[11] || f[8] || f[1]) &&
           (!f[8] || !f[7] || !f[10]) && (f[5] || f[15] || f[6]) && (f[7] || !f[6] || !f[5]) &&
           (!f[6] || f[1] || f[11]) && (!f[0] || f[9] || f[5]) && (f[13] || !f[12] || !f[7]) &&
           (f[15] || !f[7] || f[0]) && (f[7] || !f[6] || f[8]) && (!f[1] || !f[9] || !f[4]) &&
           (f[4] || !f[14] || f[7]) && (f[10] || f[7] || f[13]) && (!f[11] || f[8] || !f[2]) &&
           (!f[9] || !f[7] || !f[13]) && (!f[8] || f[13] || f[7]) && (!f[9] || f[12] || f[14]) &&
           (f[3] || !f[7] || !f[14]) && (!f[15] || !f[10] || !f[7]) && (!f[1] || f[8] || f[7]) &&
           (f[9] || !f[8] || f[1]) && (f[9] || f[8] || !f[11]) && (!f[3] || !f[9] || !f[6]) &&
           (!f[1] || !f[10] || f[11]) && (!f[6] || !f[9] || !f[1]) && (!f[5] || !f[7] || f[10]) &&
           (f[15] || !f[5] || !f[11]) && (!f[6] || f[0] || !f[4]) && (f[14] || f[15] || !f[12]) &&
           (!f[14] || !f[1] || f[2]) && (f[10] || f[11] || f[1]) && (f[4] || !f[0] || f[5]) &&
           (!f[13] || !f[11] || !f[1]) && (!f[0] || !f[1] || f[15]) && (!f[1] || f[15] || f[0]) &&
           (!f[3] || f[8] || !f[10]) && (!f[4] || f[1] || f[5]) && (!f[7] || !f[15] || f[11]) &&
           (!f[10] || f[2] || !f[1]) && (f[2] || !f[14] || !f[10]) && (f[11] || f[7] || !f[10]) &&
           (f[0] || !f[10] || !f[8]) && (f[3] || !f[0] || !f[4]) && (f[14] || !f[8] || f[12]) &&
           (f[3] || !f[6] || !f[7]) && (f[3] || f[10] || !f[14]) && (f[10] || !f[5] || f[3]) &&
           (f[9] || !f[6] || !f[0]) && (f[2] || !f[6] || f[0]) && (!f[0] || !f[8] || !f[10]) &&
           (f[7] || !f[12] || f[3]) && (f[3] || f[10] || !f[0]) && (!f[12] || f[3] || !f[0]) &&
           (f[3] || !f[0] || f[9]) && (f[9] || f[4] || !f[15]) && (f[2] || !f[15] || f[9]) &&
           (!f[4] || f[13] || f[10]) && (f[2] || !f[12] || !f[14]) && (!f[8] || f[14] || !f[7]) &&
           (f[6] || f[12] || f[1]) && (!f[10] || !f[1] || !f[0]) && (f[7] || !f[12] || f[8]) &&
           (f[13] || f[5] || f[12]) && (f[14] || !f[0] || !f[5]) && (!f[6] || !f[1] || !f[0]) &&
           (!f[3] || f[4] || f[5]) && (!f[7] || !f[14] || f[8]) && (f[4] || !f[3] || f[8]) &&
           (f[6] || f[2] || f[1]) && (f[2] || !f[14] || f[11]) && (!f[9] || !f[6] || f[1]) &&
           (!f[14] || !f[8] || !f[6]) && (!f[15] || !f[10] || !f[3]) && (f[12] || f[1] || !f[7]) &&
           (f[7] || !f[15] || !f[12]) && (!f[1] || !f[13] || !f[11]) && (f[14] || !f[4] || !f[3]) &&
           (!f[10] || f[6] || f[2]) && (f[5] || !f[12] || f[4]) && (!f[5] || !f[0] || f[12]) &&
           (!f[1] || !f[14] || !f[9]) && (f[14] || !f[12] || !f[7]) && (f[12] || f[3] || !f[15]) &&
           (f[8] || !f[4] || f[10]) && (f[14] || f[3] || f[6]) && (!f[14] || !f[9] || f[11]) &&
           (f[6] || f[15] || f[2]) && (f[13] || !f[11] || !f[14]) && (!f[8] || !f[0] || f[15]) &&
           (f[4] || f[8] || !f[15]) && (!f[5] || !f[1] || f[6]) && (f[12] || f[3] || f[15]) &&
           (!f[12] || !f[14] || !f[7]) && (f[15] || !f[8] || f[11]) && (f[4] || !f[9] || !f[7]) &&
           (!f[9] || f[3] || !f[10]) && (!f[10] || f[13] || !f[2]) && (f[6] || f[13] || !f[12]) &&
           (f[1] || !f[12] || !f[14]) && (f[12] || !f[14] || !f[5]) && (f[9] || !f[0] || !f[4]) &&
           (!f[9] || !f[8] || !f[6]) && (!f[13] || !f[0] || f[7]) && (!f[3] || !f[4] || f[13]) &&
           (f[10] || f[15] || f[14]) && (f[10] || f[3] || f[0]) && (!f[11] || f[5] || f[0]) &&
           (!f[6] || f[3] || f[4]) && (f[7] || f[4] || f[2]) && (!f[6] || f[11] || !f[12]) &&
           (f[11] || !f[2] || f[13]) && (f[13] || f[8] || !f[14]) && (!f[12] || !f[6] || f[9]) &&
           (f[1] || !f[8] || !f[2]) && (f[2] || f[4] || f[3]) && (!f[11] || f[1] || !f[0]) &&
           (!f[13] || !f[12] || f[9]) && (f[3] || !f[4] || f[9]) && (f[5] || f[8] || f[9]) &&
           (f[12] || f[4] || !f[5]) && (!f[15] || f[1] || f[14]) && (!f[4] || f[12] || !f[0]) &&
           (!f[13] || !f[7] || f[11]) && (f[4] || f[3] || f[12]) && (!f[13] || !f[5] || f[10]);
}

static int policy_b(const int *f) {
    return (f[16] || !f[24] || f[27]) && (!f[22] || f[27] || !f[19]) && (f[22] || f[25] || !f[29]) &&
           (f[29] || !f[16] || !f[22]) && (!f[26] || !f[18] || f[25]) && (f[20] || !f[22] || !f[21]) &&
           (!f[25] || !f[29] || f[20]) && (f[23] || !f[25] || !f[20]) &&
           (!f[19] || !f[18] || !f[21]) && (f[23] || f[18] || !f[24]) && (f[26] || f[27] || !f[24]) &&
           (f[26] || !f[31] || !f[28]) && (!f[21] || f[18] || !f[27]) && (!f[25] || f[30] || f[24]) &&
           (f[17] || !f[21] || !f[24]) && (f[17] || !f[29] || !f[31]) && (f[23] || f[31] || !f[29]) &&
           (!f[25] || f[23] || f[31]) && (f[21] || !f[26] || !f[22]) && (!f[17] || f[18] || f[16]) &&
           (f[31] || !f[24] || !f[23]) && (f[21] || !f[23] || f[19]) && (!f[25] || !f[29] || f[31]) &&
           (f[17] || !f[19] || f[23]) && (!f[26] || !f[23] || f[28]) && (!f[25] || f[19] || f[21]) &&
           (!f[29] || f[24] || !f[19]) && (f[20] || f[26] || !f[17]) && (!f[26] || f[19] || !f[31]) &&
           (f[30] || !f[22] || !f[27]) && (!f[22] || f[27] || f[25]) && (f[23] || !f[27] || f[29]) &&
           (f[21] || f[18] || !f[20]) && (f[28] || !f[16] || f[27]) && (!f[30] || !f[21] || f[24]) &&
           (!f[24] || !f[28] || f[16]) && (f[21] || f[30] || f[18]) && (!f[24] || !f[26] || f[22]) &&
           (f[19] || f[22] || !f[16]) && (f[21] || f[26] || !f[29]) && (f[20] || !f[23] || !f[19]) &&
           (f[29] || !f[31] || !f[21]) && (f[24] || f[22] || !f[27]) && (f[18] || f[26] || !f[21]) &&
           (f[31] || !f[26] || !f[16]) && (!f[25] || f[18] || f[21]) && (!f[28] || f[24] || !f[17]) &&
           (f[19] || f[31] || !f[17]) && (!f[18] || !f[22] || f[24]) && (!f[19] || f[16] || f[31]) &&
           (f[30] || f[29] || f[27]) && (f[22] || !f[16] || !f[30]) && (!f[17] || f[20] || !f[31]) &&
           (!f[23] || !f[28] || !f[18]) && (f[23] || !f[21] || !f[18]) &&
           (!f[30] || !f[16] || !f[22]) && (!f[25] || f[19] || f[18]) && (f[20] || f[28] || !f[16]) &&
           (f[24] || !f[31] || !f[27]) && (f[29] || !f[20] || f[18]) && (f[21] || f[23] || !f[16]) &&
           (f[18] || !f[28] || !f[24]) && (!f[21] || f[20] || !f[16]) && (f[18] || !f[24] || !f[22]) &&
           (f[20] || !f[17] || !f[29]) && (f[28] || !f[29] || !f[27]) && (f[18] || !f[17] || !f[26]) &&
           (!f[19] || !f[24] || f[27]) && (!f[25] || !f[26] || !f[19]) && (!f[29] || f[21] || f[26]) &&
           (!f[19] || !f[26] || f[22]) && (f[21] || f[23] || !f[31]);
}

static int policy_c(const int *f) {
    return (!f[27] || !f[31] || !f[22]) && (!f[24] || f[21] || !f[17]) &&
           (f[31] || !f[19] || !f[26]) && (f[27] || !f[19] || !f[18]) && (!f[24] || !f[31] || f[30]) &&
           (!f[26] || !f[25] || f[28]) && (!f[28] || f[24] || f[21]) && (f[27] || f[28] || !f[29]) &&
           (f[19] || !f[27] || !f[20]) && (!f[30] || !f[29] || !f[21]) && (!f[23] || f[31] || f[19]) &&
           (!f[27] || !f[24] || f[21]) && (!f[28] || f[23] || !f[30]) && (f[25] || f[18] || !f[21]) &&
           (!f[16] || !f[17] || !f[29]) && (f[18] || !f[21] || f[27]) && (f[23] || !f[29] || f[17]) &&
           (!f[25] || !f[27] || !f[18]) && (!f[27] || f[16] || !f[31]) && (f[31] || f[26] || !f[23]) &&
           (!f[24] || f[27] || f[29]) && (f[27] || f[18] || f[29]) && (f[23] || !f[25] || !f[20]) &&
           (!f[29] || !f[21] || !f[18]) && (!f[27] || f[31] || !f[28]) && (!f[29] || f[22] || f[17]) &&
           (f[17] || f[19] || !f[16]) && (f[29] || f[30] || f[16]) && (!f[19] || f[17] || !f[27]) &&
           (f[31] || f[21] || !f[23]) && (!f[28] || !f[30] || !f[17]) && (!f[31] || f[28] || f[29]) &&
           (f[30] || !f[20] || f[23]) && (!f[27] || f[22] || f[18]) && (!f[16] || !f[19] || f[22]) &&
           (f[18] || f[26] || !f[31]) && (f[20] || !f[16] || f[17]) && (!f[18] || f[27] || !f[26]) &&
           (!f[19] || !f[26] || !f[24]) && (f[28] || !f[21] || !f[22]) && (f[18] || f[31] || !f[29]) &&
           (f[30] || f[23] || !f[28]) && (!f[26] || f[27] || !f[16]) && (!f[20] || !f[27] || f[31]) &&
           (f[16] || !f[20] || !f[17]) && (!f[29] || f[17] || !f[27]) &&
           (!f[30] || !f[26] || !f[31]) && (f[18] || f[26] || f[30]) && (!f[24] || f[28] || !f[30]) &&
           (!f[31] || !f[17] || !f[23]) && (f[20] || !f[23] || f[24]) && (!f[24] || !f[18] || f[25]) &&
           (f[22] || !f[21] || !f[17]) && (!f[22] || !f[31] || !f[27]) && (f[29] || f[30] || !f[20]) &&
           (f[27] || !f[26] || !f[28]) && (f[19] || f[29] || !f[25]) && (f[31] || !f[28] || f[30]) &&
           (f[16] || f[19] || !f[23]) && (f[28] || !f[24] || !f[18]) && (!f[20] || f[16] || !f[21]) &&
           (!f[19] || f[17] || f[29]) && (!f[24] || !f[20] || !f[21]) && (f[28] || f[30] || !f[26]) &&
           (f[31] || f[18] || !f[20]) && (!f[29] || f[18] || f[27]) && (f[16] || f[30] || f[27]) &&
           (f[26] || f[30] || f[29]) && (!f[20] || f[23] || f[25]) && (!f[21] || !f[17] || !f[29]) &&
           (!f[25] || !f[30] || f[27]) && (!f[19] || f[28] || f[24]);
}

static int policy_d(const int *f) {
    return (f[40] || f[32] || !f[34]) && (f[43] || !f[47] || f[35]) && (!f[33] || f[39] || f[32]) &&
           (!f[34] || !f[41] || f[42]) && (f[42] || f[40] || !f[38]) && (!f[44] || f[33] || f[42]) &&
           (!f[43] || f[40] || !f[36]) && (!f[41] || !f[47] || !f[40]) &&
           (!f[32] || !f[34] || !f[36]) && (!f[43] || f[38] || f[33]) && (f[38] || f[36] || f[39]) &&
           (!f[42] || f[36] || f[46]) && (f[39] || f[38] || !f[33]) && (!f[46] || !f[47] || !f[41]) &&
           (f[45] || f[32] || !f[44]) && (f[35] || !f[36] || !f[44]) && (f[40] || !f[33] || f[35]) &&
           (!f[45] || !f[39] || f[35]) && (f[42] || f[34] || f[39]) && (!f[43] || !f[38] || !f[41]) &&
           (!f[45] || f[33] || !f[38]) && (f[36] || !f[41] || !f[32]) && (f[32] || !f[39] || f[41]) &&
           (f[41] || f[38] || !f[33]) && (!f[38] || f[42] || !f[33]) && (f[42] || f[46] || f[32]) &&
           (f[34] || !f[42] || !f[39]) && (f[37] || !f[33] || !f[35]) &&
           (!f[42] || !f[34] || !f[40]) && (!f[37] || f[36] || !f[33]) &&
           (!f[38] || !f[44] || !f[34]) && (!f[41] || !f[47] || !f[42]) &&
           (!f[44] || !f[47] || !f[36]) && (f[47] || f[36] || f[39]) && (!f[37] || !f[39] || !f[38]) &&
           (f[44] || !f[42] || f[39]) && (!f[42] || !f[43] || f[46]) && (!f[34] || !f[47] || !f[32]) &&
           (!f[42] || f[39] || !f[32]) && (f[41] || !f[40] || f[37]) && (!f[41] || !f[32] || f[44]) &&
           (f[32] || f[35] || !f[38]) && (f[46] || f[35] || f[33]) && (f[38] || !f[33] || !f[45]) &&
           (f[41] || f[32] || !f[45]) && (!f[37] || f[44] || !f[40]) && (!f[33] || f[46] || f[34]) &&
           (f[34] || f[45] || !f[43]) && (!f[46] || f[44] || f[47]) && (f[32] || f[33] || f[38]) &&
           (!f[47] || !f[44] || f[45]) && (f[46] || !f[47] || !f[40]) && (!f[34] || !f[41] || f[42]) &&
           (!f[32] || f[46] || f[36]) && (!f[44] || f[36] || f[35]) && (f[45] || f[41] || f[32]) &&
           (!f[46] || !f[44] || f[34]) && (f[43] || !f[44] || f[45]) && (!f[46] || f[44] || !f[35]) &&
           (f[45] || !f[41] || f[32]) && (f[40] || f[47] || !f[36]) && (!f[41] || !f[36] || f[32]) &&
           (!f[46] || f[47] || !f[43]) && (!f[33] || !f[40] || !f[41]) &&
           (!f[45] || !f[34] || !f[35]) && (f[41] || !f[45] || !f[40]) &&
           (!f[47] || !f[37] || f[44]) && (!f[35] || f[33] || !f[44]) && (f[47] || f[37] || !f[32]) &&
           (!f[44] || f[34] || !f[36]) && (f[41] || !f[38] || f[37]) && (!f[33] || f[47] || !f[40]);
}

static int policy_e(const int *f) {
    return (!f[41] || f[46] || f[44]) && (f[42] || !f[34] || !f[39]) && (!f[41] || !f[39] || f[47]) &&
           (!f[39] || !f[38] || f[46]) && (f[37] || f[39] || !f[35]) && (f[39] || !f[47] || f[40]) &&
           (f[41] || !f[40] || f[45]) && (!f[43] || !f[47] || !f[36]) && (f[40] || !f[44] || f[37]) &&
           (!f[38] || f[34] || f[37]) && (!f[45] || f[34] || f[43]) && (!f[42] || !f[39] || !f[45]) &&
           (!f[33] || !f[46] || f[41]) && (!f[37] || f[47] || !f[44]) && (!f[35] || !f[42] || f[45]) &&
           (!f[40] || f[36] || f[34]) && (f[36] || !f[39] || f[47]) && (!f[42] || !f[37] || !f[39]) &&
           (f[36] || f[39] || !f[47]) && (f[47] || f[33] || !f[36]) && (f[34] || !f[42] || f[38]) &&
           (f[47] || !f[40] || f[32]) && (!f[38] || f[37] || !f[47]) && (f[47] || !f[34] || f[40]) &&
           (f[34] || f[32] || f[35]) && (!f[40] || f[47] || f[33]) && (f[32] || f[45] || f[40]) &&
           (f[33] || f[47] || !f[43]) && (!f[34] || f[35] || f[45]) && (f[34] || !f[46] || !f[43]) &&
           (f[36] || !f[41] || !f[46]) && (f[45] || !f[36] || !f[42]) && (!f[44] || f[46] || !f[34]) &&
           (f[44] || f[35] || !f[41]) && (!f[47] || f[32] || f[42]) && (!f[43] || !f[39] || !f[47]) &&
           (!f[33] || f[39] || f[40]) && (!f[38] || f[43] || !f[45]) && (f[41] || f[43] || f[39]) &&
           (f[35] || f[39] || f[42]) && (!f[37] || !f[40] || f[35]) && (!f[32] || f[38] || !f[37]) &&
           (f[39] || f[32] || !f[45]) && (!f[41] || f[38] || !f[45]) && (!f[34] || f[47] || !f[44]) &&
           (!f[40] || !f[47] || f[34]) && (f[37] || !f[46] || !f[36]) && (!f[34] || !f[45] || f[40]) &&
           (f[42] || f[32] || f[40]) && (f[34] || !f[46] || f[45]) && (f[45] || !f[41] || f[43]) &&
           (!f[44] || f[47] || f[36]) && (!f[34] || !f[38] || !f[37]) && (!f[45] || f[46] || f[33]) &&
           (!f[43] || !f[40] || !f[34]) && (!f[34] || !f[43] || !f[40]) &&
           (!f[32] || f[40] || !f[42]) && (!f[36] || !f[42] || f[40]) && (f[35] || f[45] || !f[40]) &&
           (f[33] || !f[43] || f[44]) && (f[46] || f[41] || !f[40]) && (f[36] || !f[34] || f[38]) &&
           (!f[42] || !f[39] || !f[40]) && (f[33] || !f[42] || f[39]) && (!f[41] || !f[38] || f[43]) &&
           (f[45] || !f[35] || !f[40]) && (f[43] || !f[38] || !f[32]) && (!f[33] || !f[43] || f[32]) &&
           (!f[39] || !f[40] || !f[44]) && (f[47] || f[33] || !f[44]) && (!f[40] || f[46] || f[33]) &&
           (f[39] || !f[43] || !f[47]);
}

/* Build-profile diagnostics. */
static const unsigned int slot_weights[371][6] = {
    { 0x0971b7c4u, 0x97b1165fu, 0x42f8eda1u, 0xd13c513au, 0x4d645fa6u, 0x8a831817u },
    { 0xd67e4d92u, 0x25abd89bu, 0x2abc5619u, 0x48a7c825u, 0x64c184fau, 0x3cbb7daau },
    { 0xf3e452f2u, 0xf15ce760u, 0x449e78e4u, 0xeca9bad1u, 0x162794bfu, 0xcbc16f01u },
    { 0x2966493du, 0x76e9c809u, 0x08bd9d96u, 0xf4d6d235u, 0xead50263u, 0x29ec148cu },
    { 0xbed3e91cu, 0x343a2c9fu, 0x0a734d03u, 0x959575feu, 0xfe72c33bu, 0xbdcdc219u },
    { 0xa63cf5f9u, 0x7d791a3cu, 0x2694e1f7u, 0xb79db4dfu, 0xb6ab9f1au, 0xcc9ff851u },
    { 0xd921bf95u, 0x0727d4dau, 0x0dfafe39u, 0x72488b81u, 0xdda4dd1eu, 0xef4d6ee6u },
    { 0x84488709u, 0xe14c1d7eu, 0x93afd954u, 0xbc2c8e3eu, 0xa562d07cu, 0xf9fc2f72u },
    { 0xad989a70u, 0x8b9b7cefu, 0xbf77d38du, 0x4630de19u, 0x796ce0e9u, 0xb25a55f4u },
    { 0x08d213b7u, 0x86ad9101u, 0x08050a4eu, 0x79c919c1u, 0xc92830e1u, 0x3dbf2458u },
    { 0xc93de18fu, 0x82e2e271u, 0x2b420dd8u, 0x627e79c7u, 0xf045f6e0u, 0x4087c813u },
    { 0xd37e6749u, 0xe973d4d0u, 0x27a0018au, 0x466b3aa8u, 0xb70da03bu, 0x68b49734u },
    { 0x82f5e35du, 0x233911c0u, 0x753340fdu, 0xa06bcdfeu, 0xe4479493u, 0x3c51acd4u },
    { 0x48740684u, 0xc53c9fd5u, 0xfc639b8bu, 0x825dc254u, 0x86dd8a43u, 0x1b5d04ffu },
    { 0xaad7c8a8u, 0xb42f9784u, 0xe2a22af7u, 0xac39e5f4u, 0x4436a18fu, 0x18a0e333u },
    { 0xdcf91c31u, 0x234fbb23u, 0x504c2658u, 0xadaab2c3u, 0x1463b16du, 0x7cbdd8d7u },
    { 0x2b14ea2bu, 0x93393ef3u, 0x153ac151u, 0x1236b08bu, 0x064c8d98u, 0xdd482bdfu },
    { 0xabb4afcdu, 0xd6dbc7a1u, 0x9980fbbcu, 0xb37301c6u, 0x0a6bf001u, 0xd2849169u },
    { 0x4bf74313u, 0x38113ebcu, 0x470b02aau, 0x54ffcaa8u, 0x719f9212u, 0x9f1c9935u },
    { 0x40e1ec96u, 0x3e98c4f6u, 0x0311b3b0u, 0x17c497dcu, 0x9ba83d9cu, 0x5009f30du },
    { 0x1c962909u, 0xc4220e93u, 0xc61f162fu, 0x7ccaa901u, 0xf775a447u, 0xc1d96d1au },
    { 0xc7b73bd2u, 0x881a7f0cu, 0x83bdc177u, 0x7813bb57u, 0xcb41206au, 0xb2372ff6u },
    { 0x4be3e2e9u, 0x2c28ded6u, 0x6d27c91fu, 0x3a33269cu, 0xe0add80du, 0xdd9ee69fu },
    { 0x41c1a6beu, 0x198ce915u, 0x195e9b60u, 0x533fe66cu, 0x0a526d3cu, 0xe873650du },
    { 0xb1548e26u, 0xb6154826u, 0x9ce6b81bu, 0x495a38d0u, 0x0aab8722u, 0x971583ecu },
    { 0x139cab5cu, 0x2e1c1e21u, 0xa802141bu, 0x0e3909b2u, 0xbc75f5ebu, 0x8e9082b8u },
    { 0xf8eb0d21u, 0x38f4d306u, 0x926ff1aau, 0x13f59003u, 0x4492c953u, 0x66cdeeebu },
    { 0x4b4684b8u, 0xfe40a653u, 0x0d47ec5cu, 0xffddcc2du, 0x7957df1eu, 0x0ea2df01u },
    { 0x467b8fefu, 0xb183d775u, 0xce5eb7ccu, 0xf67449f7u, 0x4497120cu, 0xdeb2e4dbu },
    { 0x97a56edau, 0x257fecb1u, 0x631ebda6u, 0x647d16d6u, 0x4ca7ef92u, 0x10aef25cu },
    { 0x89fcc0e7u, 0xef07241bu, 0x4c6fb737u, 0x778369f3u, 0x92e06861u, 0xa5d70b92u },
    { 0x08207dd4u, 0x6aaffc90u, 0x1976b3cbu, 0x2a55d3c0u, 0x50ed7ef0u, 0x2aa0b17au },
    { 0xf2ff44f1u, 0xe7c06c1cu, 0xbb8e7226u, 0x9273f89cu, 0xc81b2c19u, 0xafd813a7u },
    { 0x5d1079d4u, 0x26c4f50eu, 0xc1640290u, 0x7781f430u, 0x709f85f4u, 0x7b1edfdau },
    { 0x725b4ee7u, 0x8cc3743eu, 0xc192c766u, 0xfaa21b29u, 0x887b1187u, 0xc52771bbu },
    { 0xae075810u, 0x706b71a2u, 0x4e553c13u, 0xb4d2982bu, 0x6010a025u, 0x2234873bu },
    { 0x079f9dfeu, 0xc2f3026fu, 0x7e14d344u, 0xe306b57au, 0xf9be2e41u, 0x2f3c2011u },
    { 0x85018328u, 0xe5dfd534u, 0xcea534dfu, 0x4930177eu, 0xd1d0b6cdu, 0x3fabfc8au },
    { 0xdfd15f71u, 0x3acb3952u, 0xf8321943u, 0x8224b969u, 0x76eb29e4u, 0x17a01fe5u },
    { 0x169aef13u, 0x26002f7au, 0xd2970f18u, 0x8590ca6fu, 0x111ae334u, 0x78877913u },
    { 0xcec54201u, 0x24d2bd9cu, 0x95ef2be4u, 0xb4864fd3u, 0xde4d8812u, 0xe0aabb9bu },
    { 0xf87ccf55u, 0xb5a420cdu, 0x45796c00u, 0xcb257b7eu, 0x4738c92du, 0x1bfa398fu },
    { 0xd489afbbu, 0xf758c330u, 0xd16c2d87u, 0x3a72ccc4u, 0xe44a282eu, 0x94c4c41au },
    { 0xc447d6fau, 0x95f99489u, 0xba058bd1u, 0x5c7ae370u, 0x736d73abu, 0xfd61c8feu },
    { 0x8a852b07u, 0x8eef1a45u, 0x4f14ac76u, 0xa3a59c5fu, 0x527a65a6u, 0x8f34bbc4u },
    { 0x844afc60u, 0xc2cb468eu, 0x6e4512edu, 0x05a7ff49u, 0x2f1b8b32u, 0xd17f5154u },
    { 0xc181ead8u, 0x80b0e2dfu, 0x86644733u, 0x195b9c3cu, 0x3605fec1u, 0xa3c20c4cu },
    { 0x9201d8d5u, 0x99615c61u, 0x3a4025fdu, 0x22cbe1a0u, 0x0bc759d0u, 0x2638647cu },
    { 0x21aa7f88u, 0x25cc4ab9u, 0x141f8442u, 0x8c77facbu, 0xcb018872u, 0x11602b5du },
    { 0x75a38ab4u, 0xf751eafau, 0x7664c65au, 0xd0915985u, 0xbfce60a6u, 0xbf2bfd3eu },
    { 0x2a9897a7u, 0xeb49a436u, 0x54065fb9u, 0xaa8f681au, 0xeda40dd4u, 0x48b6c63bu },
    { 0xb6f8d06au, 0x5a3793feu, 0xb2e82bcbu, 0x290b147eu, 0xcfb90596u, 0xe6e2c37cu },
    { 0xedde1439u, 0xf9692ed0u, 0x0155c8ebu, 0xb578315cu, 0xf6e77f20u, 0x2491cc5eu },
    { 0x0e448385u, 0x0945249au, 0x701e3eb2u, 0xfbf13c4bu, 0x05e3680fu, 0x6c017c3fu },
    { 0x47689befu, 0x6d89a409u, 0x6e8c26d3u, 0x7ad56076u, 0xcb7dd75fu, 0x39085b58u },
    { 0xfb64fdabu, 0x89888e47u, 0xc3abd15du, 0xd8fb6c17u, 0x46bc7d99u, 0x10e8a6d3u },
    { 0xc6fde522u, 0xa213a141u, 0x67455b14u, 0x7aa1827au, 0x0ae03331u, 0x7752159bu },
    { 0xe0a91a9fu, 0xabead941u, 0x006cd71au, 0xaab6bc29u, 0x345d2907u, 0x3d9ff5bfu },
    { 0xdae323aeu, 0xf9f60af3u, 0xe8872650u, 0x67aed82eu, 0xdc06a27au, 0xa917d122u },
    { 0x5e36d54bu, 0xf1988321u, 0xb578ae43u, 0xd874cc03u, 0x8a44f09au, 0x4f0aa1cdu },
    { 0xf046928au, 0xdf002ed0u, 0x04fb3d7bu, 0x80287517u, 0x9467a804u, 0xf22b4003u },
    { 0x1fefa4a3u, 0x0eebf19fu, 0x1624fdf5u, 0xc967f6cdu, 0x7aea201fu, 0xd0350a97u },
    { 0x72cfdedfu, 0x617d00a5u, 0x8da87d76u, 0x335ae9b7u, 0x94c65df1u, 0xeea915bfu },
    { 0x2485676au, 0x153e6f9fu, 0x1d1efeb3u, 0x1ca61bf0u, 0xf96fa7dfu, 0xac9d54beu },
    { 0xe02faa73u, 0x03f4900au, 0x1a446d5bu, 0x295bb0b0u, 0x63764cd1u, 0xf67d7d46u },
    { 0x89eca2b5u, 0x0f989cfcu, 0x978343abu, 0x7f8594f8u, 0x6c6c276eu, 0x9cc5c8f3u },
    { 0x79d64309u, 0x2092bb2eu, 0xb67ddce7u, 0x39be115du, 0x67687982u, 0x41fa81abu },
    { 0xf24312d9u, 0x7eb4dd45u, 0xfe76c1c7u, 0x038bc2bfu, 0x17dd4fbfu, 0x32430795u },
    { 0x3c39cae8u, 0x8d6e53eau, 0x4354ee40u, 0x9ddb355au, 0x13fbfae2u, 0x9d554fb5u },
    { 0x2e51a48eu, 0xb7e880a4u, 0xcf03aebfu, 0x33648ce1u, 0x0aeb6437u, 0xf9580effu },
    { 0x9e80438bu, 0x2e44162bu, 0xa5cee41cu, 0xd0b562d5u, 0x44cd4689u, 0x3d3d8f59u },
    { 0x61e0980cu, 0xa1d8f05au, 0x9a1d02b9u, 0x81eb4077u, 0x30d65ec9u, 0xb235f41eu },
    { 0x7859928bu, 0x1b33f4beu, 0x99e3a15eu, 0x3d87f587u, 0x66c1457fu, 0x32b7d073u },
    { 0xbea95d97u, 0x66f41d68u, 0xfa6ea875u, 0x99a26004u, 0xa32ce7b8u, 0x6498ca75u },
    { 0x25262786u, 0x5934370eu, 0x9b36b807u, 0x47602065u, 0x1d1c5f82u, 0x135ed344u },
    { 0x78f46241u, 0x8f2cf769u, 0xd51c3a42u, 0x3caff17au, 0x9e449977u, 0x6d5fc635u },
    { 0x7798ec98u, 0x7ef68fa1u, 0x7861942cu, 0xa652d9e7u, 0xb1356324u, 0xb862d8b1u },
    { 0x2cca05bfu, 0x9fbe85f1u, 0x064d7a2au, 0x41d18025u, 0x1887a3d5u, 0xf0953a1eu },
    { 0x985bd851u, 0xe3155198u, 0x90b11088u, 0x653dc92au, 0xcfe5a3f0u, 0x93cdba08u },
    { 0xa0c5bf72u, 0x063b565au, 0xbc574953u, 0x10809124u, 0x96aff2bau, 0x3d30b518u },
    { 0x62b67a54u, 0xfff31ceeu, 0xe26befa9u, 0xbbdf2f69u, 0x8454f426u, 0x1656c8fdu },
    { 0xcdadbc8eu, 0xa9af7d80u, 0xa6aa2c4du, 0x14f958c6u, 0x71bea8e8u, 0xff3b0d31u },
    { 0x089ad32du, 0x6c452674u, 0x0cee0740u, 0x4a12f061u, 0x935aade4u, 0x31cabdc6u },
    { 0x5681f3dfu, 0x09a46784u, 0x1bfadca4u, 0x4589081bu, 0xe051f9a5u, 0x73246d23u },
    { 0xe9e5aaa5u, 0xe4607136u, 0xf5ad83e6u, 0x696a84d9u, 0x3eee1d89u, 0x207b639bu },
    { 0xf8c32065u, 0x6c55d770u, 0x2beebb69u, 0xc5c76167u, 0x1eb49239u, 0xa7cc6051u },
    { 0xf3750889u, 0x52783ab8u, 0xa8380525u, 0x8fe701a1u, 0x38930334u, 0x552a32d9u },
    { 0x4bfea936u, 0x295eaeeau, 0xb3f5110au, 0x2f936e60u, 0xc3b4fe89u, 0x08ec10fau },
    { 0x7e4db302u, 0x6b1ce196u, 0xe160c669u, 0x4e3d6be0u, 0x926de90eu, 0x3b9a1772u },
    { 0xe0bf827cu, 0x9aaddc3cu, 0x2b732835u, 0xff3eddbau, 0x4a416f47u, 0xf8eceec4u },
    { 0xfd15a746u, 0xcdb2687du, 0x1b87c627u, 0x52880bd1u, 0x1e4d0fbcu, 0xd950cb09u },
    { 0x33ed2afbu, 0xfe02226au, 0x4d625ae5u, 0x12c28b4cu, 0xe55ed76du, 0x5a9fa911u },
    { 0xee741688u, 0x0f6ca1f1u, 0x2c515cf4u, 0xf334510fu, 0x247b58edu, 0xdcf1ee02u },
    { 0x2077a9e9u, 0x81ee65b7u, 0x2c19fd4bu, 0xf01f8623u, 0xf1efdef1u, 0x1efb7a0fu },
    { 0x49a8d57bu, 0x519717c1u, 0x118e5f9fu, 0x9e0b08a9u, 0x727260d6u, 0xb4d17191u },
    { 0x209883b5u, 0xbbbb8266u, 0xb9e9a666u, 0x1ad2b249u, 0x1c64e230u, 0xb16e5e26u },
    { 0x120b43f4u, 0x30c66854u, 0x57b7382bu, 0x4b298530u, 0x329a2d1eu, 0x7a22fe0fu },
    { 0xb33748cfu, 0x943bbe78u, 0xda55f5d2u, 0xf4fcc8c5u, 0x54b58fcbu, 0x94f0a2b4u },
    { 0xaea751a9u, 0x6ec03b40u, 0x21901e53u, 0x45bf495eu, 0x6bc7a2adu, 0x794db800u },
    { 0x8b0e902fu, 0x89677b4fu, 0xf3d6455au, 0x3b64f1e0u, 0x486e2590u, 0xe1a80124u },
    { 0x023af3a8u, 0x83a25903u, 0x55c9dc84u, 0x2ae8e1d0u, 0x35312c61u, 0x11ae3b2bu },
    { 0x3e3a8a43u, 0x1366ac77u, 0x3dc9e473u, 0x8e04a12eu, 0x453c80cdu, 0x5ad363f3u },
    { 0xba36f312u, 0x6e4b52e9u, 0x984c46eau, 0x9ac84667u, 0x05278905u, 0x962fe86du },
    { 0xea927ffcu, 0x5c80c045u, 0x7aa59201u, 0xe7bd9cadu, 0x51685a72u, 0xd07ad7aeu },
    { 0xd526535au, 0xc7f10e82u, 0x98baa3afu, 0x18a55dceu, 0x61cbcc75u, 0xee60dddeu },
    { 0xc0f5466du, 0x2f4ff652u, 0xcef4c8afu, 0x35702c38u, 0xde287184u, 0xf61e3aedu },
    { 0xab388f6du, 0x397e41a2u, 0x90c3aa21u, 0xfb0545c6u, 0x8783bbb8u, 0xafec291au },
    { 0x0257de9bu, 0x84c4ea9bu, 0x25bdbed7u, 0xc1692a75u, 0xa1c90a60u, 0x1261abe7u },
    { 0x88fd6b0du, 0x96080ae2u, 0x9e03ddf5u, 0x262f29a2u, 0x86a10f8bu, 0x54163383u },
    { 0x9db3f038u, 0xe5bea8b1u, 0x859c14bfu, 0xcd80418du, 0x1012b1e5u, 0x1451cd6eu },
    { 0x13dbad84u, 0x80627d14u, 0x76d7c81au, 0x98743229u, 0xe0142301u, 0x25f10c8cu },
    { 0x6e436493u, 0x20f1f884u, 0x92168a7au, 0x9c26dde8u, 0xec7f818au, 0xd98705a5u },
    { 0xcc7b9d19u, 0x003b74ecu, 0x39f8c800u, 0x4373ce89u, 0x2da9b8c8u, 0x24e2e80cu },
    { 0xe8bdcb11u, 0x184dbcf1u, 0x1cb0e32du, 0xefb08c9fu, 0x5d5f326eu, 0x80999df1u },
    { 0x9c881353u, 0x62d7044cu, 0x096643cfu, 0x95019311u, 0xf448fe6bu, 0xb2986e60u },
    { 0xc9139355u, 0x6040aa51u, 0x5d2a5e02u, 0x3c17100du, 0x23f12c0bu, 0x62297f3du },
    { 0x2c5d7a04u, 0x73091fb7u, 0xc5896af5u, 0x6f83e8e1u, 0xa9f51566u, 0xfa4c7295u },
    { 0xb9f30a65u, 0x763d7809u, 0x7c61bef4u, 0x4941b8f2u, 0x1e01e189u, 0xfd7089ebu },
    { 0x02b82a72u, 0xe0700689u, 0x678dc380u, 0x8300587bu, 0x1bf50891u, 0xe71d972cu },
    { 0xdd94c576u, 0x9adc0ab5u, 0x0a398eabu, 0xed3268b1u, 0x95fe5d35u, 0xe5ce74c6u },
    { 0x25c6944au, 0x29019cbdu, 0x0ce8ba5cu, 0x7d9925d8u, 0x1b45b863u, 0x2073e4f3u },
    { 0xec2c822du, 0x7f3dde7bu, 0xe2f6f3c9u, 0x4427f87cu, 0xd4e9b37du, 0x74f75c96u },
    { 0x5dcb3e49u, 0xfda05051u, 0xb1c218f8u, 0xcc9edb6fu, 0x7bab1696u, 0x3e671352u },
    { 0x30b024a8u, 0x08433738u, 0xde1c07c7u, 0x84b831c8u, 0x0e3e0d23u, 0xcc22cc03u },
    { 0xf6109de6u, 0xcd1032f2u, 0xad7e7edeu, 0x18e0762cu, 0x5fddc7d2u, 0xadf2386au },
    { 0xe3162734u, 0xa0b8545cu, 0xcbf9245au, 0x216063e1u, 0x83b41a18u, 0x1718751fu },
    { 0xe89a0bd0u, 0xce06311bu, 0xa23515a3u, 0x7b4a2ad4u, 0x0746d9f0u, 0xc70e6177u },
    { 0x5a8b1347u, 0x2dbcdf94u, 0xdd7124b8u, 0x0f55f49fu, 0x53c4da8fu, 0xf4cbc8c8u },
    { 0xfdc89e72u, 0x251ece90u, 0xc741cf29u, 0x161f7a25u, 0x6275cbddu, 0xfbfad6aau },
    { 0xa4e282c8u, 0x11bd761fu, 0xed4ee9f8u, 0x9fbccc67u, 0x76fab786u, 0x29ddda2fu },
    { 0x4ae76787u, 0xc4cae00au, 0x749b871bu, 0x5ddd177fu, 0x733cbf14u, 0x9d6cf5dbu },
    { 0x558c4c8eu, 0x7d86aaa3u, 0x79b52924u, 0x21ac7a84u, 0x23afc607u, 0x09b4e34du },
    { 0x74f18652u, 0xae550684u, 0x5bf6ce2au, 0x083e42d8u, 0x9ff2ba6bu, 0xdf0c7509u },
    { 0x5dcd308cu, 0xd3494377u, 0xc3ce53aau, 0x8b7ee022u, 0xd64bd45du, 0x4ef90184u },
    { 0xbeb3b0a4u, 0x13be2776u, 0x16b3d9d6u, 0x61dc0be3u, 0x95bf9812u, 0x97080b2eu },
    { 0x851fb0a5u, 0x3f33f3c0u, 0x336eb582u, 0x2fb934adu, 0x34f6a3dcu, 0x120bd325u },
    { 0xe4094a04u, 0x8e7bdfc2u, 0x8b3c94feu, 0xcd1d21d4u, 0x47204abau, 0x2ea8aa0eu },
    { 0x01522addu, 0x6fdbbe34u, 0xa7a25639u, 0x747067f7u, 0x961dcc4eu, 0x37936bbau },
    { 0xd8857084u, 0x0bf0f00bu, 0xaf11922eu, 0x243720e5u, 0x004e76e3u, 0x40856864u },
    { 0xab6a8de1u, 0x0807ca0au, 0x6d90a684u, 0x3c06ead3u, 0xff9e60fbu, 0x7e472842u },
    { 0xb5413ccbu, 0x51c3d7e0u, 0xe4128685u, 0x7b319717u, 0xb4c680b8u, 0xeb32b6a0u },
    { 0xd212f049u, 0xb0b27ebfu, 0x6369f381u, 0xc213e6f9u, 0xfd1f7d47u, 0xa3f5fbecu },
    { 0x3824d287u, 0xbfe51d56u, 0xa1ad477cu, 0xb7e4a318u, 0xa7a3e3e8u, 0xfab0e5afu },
    { 0x97a422dcu, 0xa687d764u, 0x4fd227d5u, 0xa0594121u, 0xf781c593u, 0x377e7ca4u },
    { 0x22873508u, 0x1fdb0b68u, 0x9e35843au, 0x80af25f3u, 0x693d1536u, 0xa0860b43u },
    { 0xe8259e71u, 0x255e55c0u, 0x3a1328f9u, 0xf798be0cu, 0x14951cebu, 0x4e2846fdu },
    { 0x80709cc6u, 0xe71d6f15u, 0x8a3da2c3u, 0x7b9ea013u, 0x301c32d4u, 0x73d7b5ddu },
    { 0xf598fccau, 0xfbb28d9cu, 0x9ad3e2a7u, 0x4bb24cb5u, 0x16a85f83u, 0x20ea4c1bu },
    { 0xd8755f27u, 0x9184379eu, 0xa86c1cbdu, 0x1e2abd5bu, 0xe55150e0u, 0x41905d5eu },
    { 0xb696be4au, 0x9c3b504fu, 0x3cd8d78eu, 0xdbf0a45au, 0x9bf0c77du, 0xaabd45f4u },
    { 0x0c370a56u, 0x24a2d483u, 0x913c2fafu, 0xc5932b66u, 0x38bed045u, 0x349a3772u },
    { 0xe06cc6ecu, 0xc91c6ff9u, 0x972b22b0u, 0xc2a9050au, 0xb4ebda94u, 0x502ab643u },
    { 0x0e594e0au, 0x924701acu, 0x5162ee2bu, 0x0e963105u, 0x79acff26u, 0xb4c0e786u },
    { 0x000ec51cu, 0x9c4a537bu, 0x41fa24afu, 0xee0e98d7u, 0x0ba6646du, 0x182359dbu },
    { 0x73213c86u, 0x2e245942u, 0x3c705101u, 0x810a0947u, 0x4fe23075u, 0xef17c17fu },
    { 0x48451ca7u, 0x5b01c8d4u, 0x63dce502u, 0x38d96f03u, 0xa31d075bu, 0x83944c1eu },
    { 0xddb4a13du, 0x0cf7c5c8u, 0x4cf66507u, 0x8ca55d00u, 0x0c2913dcu, 0x77047f91u },
    { 0xe08142ceu, 0x6d9b8b59u, 0x2a3800a1u, 0x485f766fu, 0x541c53a4u, 0xafd20bdcu },
    { 0xb9bf1fe7u, 0xa53f07d8u, 0x128991bdu, 0x41fb3c0cu, 0xcfa3b10au, 0xc27d61c9u },
    { 0x36c2b356u, 0x6dfe6d10u, 0x1447bc79u, 0x93774c48u, 0xc71cec11u, 0x123717f1u },
    { 0xafb5043fu, 0x25c65892u, 0xac903985u, 0x6f6c9e6au, 0x6782e585u, 0x9ac1922eu },
    { 0xdefde2c3u, 0x7b022540u, 0x38eda1d6u, 0x3783400du, 0x556b233du, 0x5533af6cu },
    { 0x7b1224b5u, 0xd3a3d311u, 0xc0a6719fu, 0xe5b50a7cu, 0xcd92a401u, 0xbf53b58fu },
    { 0xfd076d50u, 0x60702a76u, 0x802d333du, 0x40fe630fu, 0x47f3ccabu, 0xdf7f55a4u },
    { 0xfa1fa1dcu, 0x8b4c65d6u, 0xf2c49230u, 0x0055aeb3u, 0xcc3e08f6u, 0x9f4f72d3u },
    { 0xe4603db1u, 0x3bc3a963u, 0xb8631e18u, 0x211ad02au, 0x45af5f5cu, 0xb281a0dfu },
    { 0xa6418bf3u, 0x2d150afbu, 0xab1a5f94u, 0x042b0b63u, 0x05b15b72u, 0x67ea35efu },
    { 0x9f8454f9u, 0x874ef282u, 0x36de295au, 0x9449f7a1u, 0x6a3ae413u, 0xf25c9c95u },
    { 0x34e25cf2u, 0x324c0682u, 0xb03c1dbdu, 0xfe816234u, 0xc4f982dbu, 0xdf231fc2u },
    { 0xe2b3532au, 0x592377adu, 0xbd58fc75u, 0xbf11171bu, 0x490ba14au, 0xa78dc133u },
    { 0x51fc206bu, 0x5a63bfbau, 0xcab8e429u, 0x93cd4801u, 0x6be390d1u, 0x0ee95668u },
    { 0x988cddbbu, 0x3d0b07b6u, 0xed89f8b8u, 0x56b74146u, 0x1cd42484u, 0x3279ddacu },
    { 0x722ade42u, 0xef069db1u, 0x822f6640u, 0xd2f573ceu, 0x711f6b92u, 0xac5129fbu },
    { 0x90a0db0bu, 0x3a1804a0u, 0x1cb8a138u, 0xd0a5fd87u, 0xdf18253cu, 0x0e9ebf3du },
    { 0x04b04a64u, 0xcaaf4ea4u, 0xd1fc64d9u, 0xd52aa965u, 0xf55b5979u, 0x1718a73cu },
    { 0xfd0cff97u, 0x24e1e976u, 0x7f0cf46eu, 0xd0d3c983u, 0x54404e8eu, 0xa4aeac80u },
    { 0x5095036bu, 0xab96cc55u, 0x7a37f396u, 0xad55e202u, 0x1411a6aeu, 0x53acf2c7u },
    { 0x4ac718d9u, 0x1a7ec988u, 0xab4ef537u, 0x906e607eu, 0xc8f8cdcdu, 0x8ca6e15cu },
    { 0xa69e5f1fu, 0x3653cdf0u, 0x893b2b42u, 0xccec76d9u, 0xabd65cd9u, 0xa977cdaeu },
    { 0x0afbc7b5u, 0x6bf49764u, 0x8ae23fadu, 0xc8f1c386u, 0xbba84bcau, 0x729de516u },
    { 0xeeac9143u, 0x4cb2b421u, 0xe629f392u, 0x403b05fau, 0x01867d3fu, 0x436211ebu },
    { 0x61b5b227u, 0xf5c2f8cdu, 0xd885a37eu, 0xf4c0bff0u, 0x75f71692u, 0x51d63276u },
    { 0x1956cb25u, 0x30cbc99eu, 0xd3873502u, 0xdcffd002u, 0xa02ed8d4u, 0x073f1ed6u },
    { 0xf6796aaau, 0x1f7e5648u, 0x9df9af16u, 0x56f956f1u, 0x2b00c2d4u, 0xf19fad81u },
    { 0x58b740bfu, 0x1be401ecu, 0x828c7b18u, 0xd5520ddeu, 0x974eb24fu, 0x11da8e21u },
    { 0xc1957020u, 0xf567a279u, 0x037f5933u, 0xf7be3c45u, 0x8e92e33au, 0x974791e7u },
    { 0x69223b0cu, 0xb4c7256au, 0xfdbaed8du, 0x9b1a476bu, 0x35e8759au, 0xf62cb5d2u },
    { 0xfad82241u, 0x3fdbaee3u, 0xd12a5610u, 0x215b9006u, 0xcdd8c911u, 0xb4d8d903u },
    { 0x90c1d40cu, 0x087e02b0u, 0xb0e479bau, 0x88922c9eu, 0x5f1cd911u, 0xff05ae15u },
    { 0x0b8a5567u, 0xa9001173u, 0x5b005ba2u, 0xb4332021u, 0x4d31281du, 0x187911e1u },
    { 0x26303222u, 0xe924bf6fu, 0xa1764a98u, 0xbcfcd9b3u, 0xa2b1b513u, 0x447bd9a5u },
    { 0xb8ffd001u, 0xfa67c973u, 0x6ff9be21u, 0x4ad8df49u, 0xefeaa840u, 0x4409e344u },
    { 0xed8c6040u, 0x7971c650u, 0xb55781a7u, 0xb2cbacb5u, 0x016d932bu, 0xfeecd8e4u },
    { 0xe29fcb71u, 0xcf5a925eu, 0x6a74e29bu, 0x334ac865u, 0xdd20fb45u, 0xa54453c0u },
    { 0xdfa0b8d5u, 0x76636f08u, 0x8cbf2e7fu, 0xecc35378u, 0x811c9cb0u, 0x1ce83b9du },
    { 0xaa60ccd2u, 0x3c366cbcu, 0xd33ebf00u, 0x2d45366fu, 0xfe42ade3u, 0xca0da588u },
    { 0xc0769256u, 0xf88178cfu, 0x580b7c11u, 0xdffd946du, 0x0e7af3d7u, 0x036413c5u },
    { 0x93a00161u, 0xa9fd8c38u, 0x5b447f1fu, 0x6523155bu, 0xa4fcc8dbu, 0xc5d2cc27u },
    { 0x80234c70u, 0xcdf87121u, 0x8cb359c8u, 0xd869e4dau, 0x959a36eau, 0x41601164u },
    { 0xf84df3d7u, 0xf43e53ecu, 0xc3f0ef66u, 0xf57111efu, 0x4d01ad1eu, 0x48cad678u },
    { 0x4c49ff99u, 0x9b868034u, 0x47ea40dfu, 0x55f42b8du, 0x4e93f87cu, 0x3d44efc1u },
    { 0xfd15485du, 0x806ea34eu, 0xcac447fcu, 0xf1fa15dau, 0x301f4db8u, 0x4941e542u },
    { 0x38106579u, 0x1ec65aa2u, 0xb60c037du, 0x6c7ae9c9u, 0x769daf4eu, 0xc9e983ecu },
    { 0x1fa74971u, 0x787b5b09u, 0xed1125bdu, 0xb7e7ed82u, 0xd8812231u, 0x59a58419u },
    { 0xb6a99d68u, 0xc02e096bu, 0xf5251a15u, 0x4ea76528u, 0xf1208ab4u, 0xff105f7au },
    { 0xfbb94521u, 0xfd875b05u, 0xc50aab66u, 0xc763324du, 0xfdfc541eu, 0xb6b98222u },
    { 0xd1303369u, 0x50b9dce9u, 0x5947bba6u, 0x715eafddu, 0xb8f79944u, 0x6c6e0631u },
    { 0xb5d58b2bu, 0xd31009b3u, 0xafa79117u, 0xa1a5b475u, 0x3534f845u, 0xda3cc01bu },
    { 0x8bdc49eau, 0xb06df81cu, 0x89736fd4u, 0xdfef7611u, 0x433ff2f7u, 0xc77db026u },
    { 0x923692f9u, 0x2685f372u, 0x0491c934u, 0xa4992810u, 0xe5b6b36au, 0x1ff6df24u },
    { 0x4c0ecfcdu, 0x276f7911u, 0x9134bf7du, 0x84ef5a8bu, 0x8810ec92u, 0x96703438u },
    { 0xf1afee51u, 0x08e5c6bau, 0x98d59e05u, 0x2d2f5971u, 0x094ec1ffu, 0x2290abf5u },
    { 0x1a36e07bu, 0x0d5a938au, 0x303afd3cu, 0xbd59f4a8u, 0x1a7d43efu, 0x4f686da4u },
    { 0xd27c3cf7u, 0x31695c52u, 0x732ac14bu, 0x6cc9421cu, 0xa2f055aau, 0x6e9684d2u },
    { 0x49349b7bu, 0x8b1ab983u, 0x0cf51839u, 0x7c872540u, 0xe968228eu, 0x6cb31b4cu },
    { 0x150a1e09u, 0x0d154357u, 0xe078cc02u, 0xf4481aebu, 0x6943e58eu, 0xa1c77d43u },
    { 0xca39a552u, 0x602dbaf1u, 0x1a654c58u, 0x7dcd0d47u, 0x2d240469u, 0xc6d041a0u },
    { 0x9b179be4u, 0xe205a29du, 0x23ca0b78u, 0xab9bb11au, 0xbf098811u, 0xda636f41u },
    { 0xf67708acu, 0xd577ba0eu, 0x301823d3u, 0x14866583u, 0xaad0ee2du, 0x151fce8cu },
    { 0xd3d29829u, 0xf61d0935u, 0x73d684f8u, 0x1ef556a0u, 0xcebfebb7u, 0x24341834u },
    { 0xddc5db6eu, 0xe8ab068bu, 0x2b09a176u, 0xb31df21cu, 0xb84a1688u, 0xb11ccd3fu },
    { 0x319e5bfau, 0x44d030aau, 0xc79c5a30u, 0xc7b7fff4u, 0x3ffd1dcbu, 0x49d46489u },
    { 0x26fb14a1u, 0x2f288580u, 0xe033e552u, 0x45b718c7u, 0x8989b2c9u, 0x0caccbeeu },
    { 0xa243a131u, 0x87589768u, 0xea9a4fb2u, 0x45b7fd56u, 0x571fca6bu, 0xb2a0faf8u },
    { 0xff42e1b5u, 0x48adc5fbu, 0x3da1de1au, 0x8c8b7d52u, 0x70ce7bddu, 0xd83aeaa3u },
    { 0x9ddfdef1u, 0x08ee58dbu, 0x73ef0d51u, 0xf9d536f1u, 0x86c4e8d8u, 0xba65f3b1u },
    { 0xcaa069dbu, 0xe3bd5728u, 0x87f89e29u, 0x52d99617u, 0x2bd40584u, 0x8ee1417fu },
    { 0x6a362663u, 0xf10e7901u, 0x9281cd37u, 0x5b9503e2u, 0x4482199au, 0xdb5045cbu },
    { 0xc54e0c67u, 0x38eed337u, 0x86063f4eu, 0x8a7e7e72u, 0xdcd066cdu, 0x8d4d5b9cu },
    { 0x85fa2164u, 0xcc343480u, 0x225ebcf4u, 0x0688476bu, 0xc8b1ec46u, 0x53abfffbu },
    { 0xf211140cu, 0xf7919348u, 0x29304481u, 0xbcf32d55u, 0xa6591edau, 0xb77305b8u },
    { 0x15d0d241u, 0xe8fd32cbu, 0xe80f80d8u, 0x39b5b8dfu, 0xaaedd657u, 0x61f35288u },
    { 0xcd3977f5u, 0xf901d02cu, 0x0d2ebc52u, 0xe189e87cu, 0xa0aa75a7u, 0xe710233fu },
    { 0x21f4cef4u, 0xc9d60d66u, 0x8d990b9cu, 0x9f99ec89u, 0x6a40a4feu, 0x71479c4cu },
    { 0xc5cf8649u, 0x26f183f1u, 0x5d84e1beu, 0x87a8d48eu, 0x18da5c6au, 0xaccaae44u },
    { 0x5a714ff3u, 0x7f1948a5u, 0xb38c0047u, 0xb8a811b8u, 0xbe30ea4fu, 0x0638f9c1u },
    { 0x1a53634au, 0x3d970c2au, 0x918bc309u, 0xbba4366eu, 0x1e19c216u, 0x0a59d424u },
    { 0xd93c7f77u, 0x8693bbd2u, 0x94c4a0f5u, 0x2f62c1e8u, 0x44658587u, 0x4f25a58fu },
    { 0xaefdd8e6u, 0x28da7ce7u, 0xc22762b3u, 0xe1f3705au, 0xe6f3f75au, 0xfedd2d97u },
    { 0x3bdba7ecu, 0x1e5a8f7eu, 0x8374e618u, 0x68e614b6u, 0x26955ca4u, 0xf24dafedu },
    { 0x5b44a0ecu, 0x44319de3u, 0x5d986838u, 0x14cc13aau, 0x183b5b03u, 0xd7a46e75u },
    { 0xed4edc25u, 0xe5e19960u, 0x9dadc2a5u, 0x8a0a477eu, 0x15b931b1u, 0x99d23ca4u },
    { 0x291482d7u, 0x56f79694u, 0xef0ea1b6u, 0xe4ab88aeu, 0x0d59ee8au, 0x51f050eeu },
    { 0x2866aab8u, 0x42d0ac60u, 0x443bc1bbu, 0x4f33c76au, 0xd6e18054u, 0x14631b79u },
    { 0xced47ebau, 0xaa5b4da8u, 0x0c1ff5e9u, 0x8b1e833au, 0xa9c3bd25u, 0x9145f129u },
    { 0x0bbd1211u, 0xc0eadee0u, 0x619e874cu, 0x982b7202u, 0x6eea60e6u, 0x908500fbu },
    { 0x5d618681u, 0xa1eab7b9u, 0x8a1f3c5du, 0xbfcbfd83u, 0x0d4f8febu, 0xc2663d7eu },
    { 0x8dc2e2c8u, 0xfbe8c4bau, 0xa165257du, 0x491858b8u, 0x648d8587u, 0x5e70c88fu },
    { 0x96e223f4u, 0xe3633ff3u, 0x069359b1u, 0x1398318cu, 0x61fb40ebu, 0x45990d60u },
    { 0x8cb5cc25u, 0x7adeddb0u, 0x512caa4du, 0xbc7f11d4u, 0x435e31b4u, 0x24c75063u },
    { 0xcf2fe9b7u, 0x7b0d3ed7u, 0xd0018d84u, 0x6a828130u, 0x4929f0a0u, 0xf326e83eu },
    { 0x6e144e35u, 0xb8af3563u, 0x91966627u, 0x7fa667abu, 0x3a639bbfu, 0x4c58623du },
    { 0x3dbdc015u, 0x13b22d3bu, 0xda8390a0u, 0xd8782259u, 0x02b2bf98u, 0xf68836deu },
    { 0x8d177dfeu, 0x14856428u, 0xdde17052u, 0x2234129au, 0xc1dfa628u, 0x63fc7f4eu },
    { 0xac317aaau, 0x6ec92c83u, 0x22514268u, 0x941688d9u, 0x258da414u, 0xff7ee045u },
    { 0xa3ecf1b8u, 0x879bfd51u, 0x4e68afffu, 0x5ebd222bu, 0xcb51df20u, 0xffeb1c4cu },
    { 0xa0c958bfu, 0x65d8a213u, 0xb4eaa981u, 0xdab82698u, 0x60a74e70u, 0xd9af48b0u },
    { 0xffb0092au, 0xaf1068a8u, 0x885f77a0u, 0x3c521007u, 0xbb4c118au, 0xe51c54ffu },
    { 0x35c90876u, 0x8fa95759u, 0x98038d19u, 0xc8858f74u, 0xcd5103f1u, 0xef5c13d8u },
    { 0x02f81e63u, 0x426d58f6u, 0x35d61eb6u, 0xd344d42bu, 0xf7ffb4f7u, 0x850d6374u },
    { 0x4e59b6afu, 0x3603320au, 0x9ae7b847u, 0xef77c3d4u, 0xa432c4e1u, 0x566818ccu },
    { 0x0af78495u, 0xfbd56736u, 0xd993a12au, 0xfc69cb27u, 0x04561a18u, 0xa1badb86u },
    { 0x7c4a8f00u, 0x2907a135u, 0xffb0eb25u, 0xb7586680u, 0x2cc6fffeu, 0x3df24540u },
    { 0xfcd06723u, 0x8c66b607u, 0x2ed9b238u, 0x4f0dc1c1u, 0x19f30feau, 0xaf0493dbu },
    { 0xb239e631u, 0x85909fa3u, 0xb8f4774du, 0x4dbe5b6cu, 0x0adc9fbfu, 0x17ea5be3u },
    { 0xb735154fu, 0xabfc4ddeu, 0x94781ae6u, 0xbce68570u, 0x86fc52f9u, 0xfb512298u },
    { 0xb4a35f98u, 0x3d278994u, 0x6b276ea5u, 0xac379d4fu, 0x7485494au, 0xd46a6d01u },
    { 0x57d3c685u, 0x830550b9u, 0x75fcfb67u, 0x7c388f46u, 0x3ed06958u, 0x60e08bddu },
    { 0x5136f823u, 0x18581fdbu, 0x081d2bf4u, 0x8b7f8166u, 0xe3db2f5bu, 0x5a5f1effu },
    { 0xa54f63e7u, 0xd429c298u, 0x891c348au, 0x1efd7188u, 0xf4c48c3au, 0x4861bf52u },
    { 0xa569ff20u, 0xea7febafu, 0x6f0e76a9u, 0xc8ba1265u, 0x37e5f101u, 0xd62a8e8fu },
    { 0xa5dd0b8cu, 0x6cc8edb7u, 0x3b76f562u, 0xeb552bfcu, 0x6d961eb0u, 0x245ee648u },
    { 0x11567a19u, 0xc6716653u, 0x19cf38ddu, 0x6630162bu, 0x3506c9fbu, 0x86cbac9eu },
    { 0x7139a29fu, 0x8f480e27u, 0x4dd07000u, 0x731d4080u, 0xd1f80c59u, 0x933f8b52u },
    { 0x6f4c848du, 0x308e81cbu, 0x5abb5199u, 0xc7c5cc7cu, 0x7341140bu, 0xba7c7e6bu },
    { 0xc7a112e4u, 0x35d3c894u, 0xc8c94ab7u, 0x9dbc3b20u, 0x0cfac428u, 0x26f77ec9u },
    { 0x9af51f54u, 0x09c0e3efu, 0xa1c5bf2eu, 0x7dc13f3cu, 0x9d0b789cu, 0x8ee19df3u },
    { 0xf8826f12u, 0x8545b11fu, 0xa3ffab27u, 0x2afabf0bu, 0x2edce204u, 0xdf992136u },
    { 0x7ca50c01u, 0xe60f470eu, 0xfca24e66u, 0xeb57fc0fu, 0xf1ebdf52u, 0xa0524f41u },
    { 0x8c77b7ebu, 0x75af117au, 0x19b4d08au, 0x7169b583u, 0xbf453f14u, 0x6f174970u },
    { 0x742f1433u, 0x29fb0246u, 0xe6f1cc1au, 0x869ea067u, 0xe0170681u, 0x12873934u },
    { 0xd19f5fb1u, 0xd188276cu, 0x8a85ed75u, 0x03cb9627u, 0xf102ab12u, 0xaba8a5f0u },
    { 0xc1547b10u, 0xd496d304u, 0x5008ef8eu, 0x0e267383u, 0x4eb5bca5u, 0xa928b8f1u },
    { 0xd21ed8d1u, 0xebef1b53u, 0x8717e190u, 0x4f261205u, 0xbf4a6ed9u, 0xbb25d264u },
    { 0xd4954d69u, 0xd7aa1f75u, 0xddf4c7bfu, 0x02c4326fu, 0x930b457cu, 0x06edd0efu },
    { 0xce033317u, 0x1fcd60f1u, 0x3f603446u, 0x359d4df4u, 0x2f43e702u, 0xf2f70049u },
    { 0x0a8f8e5eu, 0x14b8850au, 0xd7429e64u, 0x333139f6u, 0xe198cfacu, 0xad0bf799u },
    { 0x3c0b7447u, 0x43f272ceu, 0xbc42c1bcu, 0xff76aafdu, 0x99461b39u, 0x1c0787fdu },
    { 0x85ea67a4u, 0xceae3e7bu, 0x304e7e0fu, 0x201bc422u, 0x58a3677du, 0x69480bc9u },
    { 0xf2b6a075u, 0xd51577b8u, 0x8a16e7dbu, 0x007805bfu, 0xa6815a59u, 0x69a594b1u },
    { 0x6c905757u, 0x2e86dc10u, 0x784c73c2u, 0xf5f35371u, 0x04a87a3au, 0x79145345u },
    { 0xf3d5e836u, 0x64a87badu, 0xed37f972u, 0xdac73154u, 0x75bd2d84u, 0x91f3558du },
    { 0xd488decdu, 0x73cce947u, 0xc4a9b72bu, 0xc244cf0du, 0x0376b7e4u, 0x86989267u },
    { 0xb84d83fdu, 0xe22d2f96u, 0xe63fe3ddu, 0x88df262bu, 0x202528c9u, 0xcba23632u },
    { 0x7223acfeu, 0x0b7f730fu, 0x9ccf6d43u, 0x392f0e44u, 0x694c8c15u, 0x2a38ced7u },
    { 0x22e3c8a1u, 0xa4712ecdu, 0xe7691df6u, 0xed65215du, 0x136981c1u, 0x754d5d06u },
    { 0x312295fdu, 0x7ce98b93u, 0x03115c52u, 0x4a5c62c3u, 0x30472271u, 0x6eed5c44u },
    { 0x0e587b3fu, 0x4a977ce5u, 0x62a34280u, 0x894cec1du, 0xcf9148dbu, 0x81b6af8au },
    { 0x5196b6a7u, 0x4aa98bb5u, 0x598c4a4eu, 0x0e647886u, 0x17771f18u, 0xa42019ccu },
    { 0x48723647u, 0xb1507a74u, 0xd5841243u, 0x65837794u, 0x5a5b9b72u, 0x8c89d2d5u },
    { 0x1e3e164cu, 0x0e73469cu, 0x35f2f363u, 0x2e5bb73du, 0xb2d2ff4fu, 0x8820289bu },
    { 0xcfe94407u, 0x888f0b83u, 0x3a427e5bu, 0xfa8c3ec7u, 0x569c729du, 0x5821a3c2u },
    { 0x6e21b1a0u, 0xff0ee2c1u, 0x798a8f01u, 0x8f37034au, 0x38c0c8feu, 0x0b8f78cau },
    { 0x2b8e973au, 0x3b51ef28u, 0x0b30321cu, 0x5a8c7a03u, 0x2e5bb036u, 0x08dd8602u },
    { 0x6369d82du, 0xae531e2au, 0xba6c6ee8u, 0x354ad8d5u, 0x91c42822u, 0xd54d19aeu },
    { 0xba876a33u, 0xf297915bu, 0x97e91d29u, 0x44229afbu, 0x12abfd0fu, 0xbd398bdeu },
    { 0x4d629595u, 0xc4643215u, 0x11081e19u, 0x4a95c43cu, 0x94f6901eu, 0x693ad3b6u },
    { 0x0cd933efu, 0xdb2d6673u, 0x49eab8b0u, 0xe607f38bu, 0x2f9f7395u, 0xd4fadeecu },
    { 0x92756454u, 0x3399a722u, 0x6451825fu, 0xa2f76772u, 0x1e507407u, 0x46ed0a2eu },
    { 0xc5926cd3u, 0xa0c742d5u, 0x90de24ddu, 0x8dfdbe13u, 0x811179ddu, 0xe148f985u },
    { 0xdbe941dfu, 0xd1a381fdu, 0xf24f0a71u, 0x1bc965b4u, 0x8336ebf4u, 0x87298cfdu },
    { 0x419f5ee9u, 0xc9d4b1feu, 0xdc7f751fu, 0x75521ff7u, 0x8bbb0670u, 0xf9322495u },
    { 0x6dd15d5fu, 0x943f71b5u, 0x94d200ccu, 0x0c62f6dfu, 0x8d593a57u, 0x8d1f4671u },
    { 0x1858ff16u, 0x6328550eu, 0x29b5db39u, 0x7ed2bc61u, 0x7492127cu, 0x35316b42u },
    { 0x4e977adfu, 0x31ee4ff5u, 0x39872abcu, 0x9e4c3a86u, 0xe5e0e6e1u, 0x10a9b085u },
    { 0xeef09c3au, 0xb5b37eacu, 0xe8b92a06u, 0x1efae6dbu, 0x9672c3edu, 0xcae4ba23u },
    { 0xab37292eu, 0x18434347u, 0xb72bae26u, 0x2d56c38cu, 0x43b95504u, 0x784b96d0u },
    { 0x969454f9u, 0x7f2432e7u, 0xa15e6499u, 0x07626a16u, 0x72a37c66u, 0x4e4dc6f9u },
    { 0x81cd14a9u, 0x52882d86u, 0x3c472ba1u, 0xe103eae7u, 0xae568e30u, 0x77c00b43u },
    { 0xc05e8790u, 0x4f137657u, 0x60541435u, 0xcff3fb88u, 0x6600a5cau, 0xe1ca1890u },
    { 0x4c4bcd87u, 0x85086feeu, 0x1b52278du, 0x00b235fdu, 0x7cca65cau, 0x332f564du },
    { 0x655d25b8u, 0xb10a8d52u, 0xe27489afu, 0xd082f202u, 0xeaaa3eabu, 0x50329a98u },
    { 0x397042e3u, 0x4e4874b3u, 0x7df0e03au, 0x2be0d803u, 0x5d2fa673u, 0xe5657ae0u },
    { 0x87282558u, 0x6fa79878u, 0x1eea8ae7u, 0xa135f9dau, 0x7c669278u, 0x9195ae1eu },
    { 0x85d8e20bu, 0xf9d12d1au, 0x9f7e3c01u, 0x89d4383bu, 0x83b9d089u, 0x86713457u },
    { 0xceef24c6u, 0x056c5a95u, 0x0b0354acu, 0x69227673u, 0x2ac88c30u, 0x5ad76e6du },
    { 0x69c7954du, 0x06371df7u, 0xf13a1c3fu, 0x4b27a309u, 0x5b9aa716u, 0xc415214du },
    { 0x1fec33d9u, 0x81ce9aa7u, 0x3f4dd0afu, 0xaa8ddf8cu, 0x2cc9fac2u, 0xa40de64bu },
    { 0x5b4b8bc2u, 0x18e8dfd2u, 0x50b71c51u, 0x8c2e126cu, 0x6d0de41cu, 0x3b669210u },
    { 0x44e2b386u, 0xb6380fe4u, 0x9c8150ceu, 0x2362f18eu, 0xadfbfc1bu, 0x4e9ea931u },
    { 0x5af6d063u, 0x2012842eu, 0xd1bfd7aau, 0xd41d2c8fu, 0x2f06cdeau, 0x98adac32u },
    { 0xe5725c60u, 0x3ab7b0bdu, 0xf8d30422u, 0xd6923db9u, 0x8b4f7a46u, 0xec0bd8eeu },
    { 0xb6bb73f8u, 0x7ab89f30u, 0x27ab3ed3u, 0xc6870612u, 0xb9ed4785u, 0x4b45030cu },
    { 0xf24a79c5u, 0x21be4eb2u, 0xa5110064u, 0x55d4b292u, 0x613ec9d2u, 0xd01019f5u },
    { 0x9d324db3u, 0xa12d97b2u, 0xcfbdfacfu, 0x2cf53ab2u, 0xa6d7e378u, 0x629566d6u },
    { 0x0e4901e1u, 0x3ff54931u, 0xb055c0cbu, 0xb37b45deu, 0x527fd64bu, 0xf07e3040u },
    { 0x9e8585c1u, 0x34a56ac8u, 0xa9ddbce7u, 0x5d0eb749u, 0xb759d9e6u, 0x72078e97u },
    { 0x53f2ecdcu, 0x813eaf90u, 0x562ce708u, 0xbf18e495u, 0xe69f2d1eu, 0xbaaa7d3du },
    { 0xfbaf5ac4u, 0x5b6d866bu, 0xdbb6a9f4u, 0xf428d6dfu, 0x9e37e76cu, 0x340d7ac0u },
    { 0x33dc236fu, 0xffbf7076u, 0x19ae7d46u, 0x65dc4c6cu, 0x0b56faf8u, 0x50e5797eu },
    { 0x3783f5ccu, 0xba30e1d3u, 0x3e11f7c9u, 0xe95faf18u, 0x1eefba4bu, 0xce9113a8u },
    { 0x0d60e756u, 0x6c4b1820u, 0x4c831698u, 0x08345662u, 0xec26759fu, 0x92336997u },
    { 0x121dcb58u, 0xcdabd684u, 0x4668698eu, 0x43e91713u, 0x83b45849u, 0x9f84f37eu },
    { 0x4fbf172cu, 0xb5ddb2cfu, 0xf5bab01au, 0xcc76d531u, 0x42e5f55fu, 0xfaf5ce2eu },
    { 0x02a0095au, 0xf70498fcu, 0x7c4013ccu, 0x286870ffu, 0x27c788c7u, 0x671cd26cu },
    { 0x0c6652e4u, 0x9feadb1eu, 0x3e305f31u, 0x362efa56u, 0xeb3a3d3du, 0x90a10428u },
    { 0x2e520984u, 0x9f61cce9u, 0x52a437edu, 0x926c01afu, 0xbc713240u, 0xe0bee8c1u },
    { 0xbe27fb4eu, 0xb656c865u, 0x543a9ef8u, 0x4b70e8b3u, 0x087ca1f1u, 0xe75fdcfcu },
    { 0x51cc8ab0u, 0x88160359u, 0xa8cb44cau, 0x6f626e0bu, 0x9b20e80au, 0xa6a30790u },
    { 0x47f804d1u, 0x8b424785u, 0x68d7b292u, 0x5e515ba4u, 0x99934f19u, 0xd4f23af2u },
    { 0xad0860d9u, 0x4a2b8c9fu, 0x5b2b3675u, 0x72ff3aabu, 0xc2cf0ab6u, 0xeb3dcf13u },
    { 0x9fe6071du, 0x0b0c1c05u, 0xd0318f26u, 0x54cffd39u, 0xc1f08872u, 0xe6f897abu },
    { 0xf387943au, 0xab498745u, 0xf0c86312u, 0xc2a2463bu, 0x89b9cc0bu, 0xaf07ee8au },
    { 0x6b3d494cu, 0x76d38656u, 0x05276f89u, 0x8205ae81u, 0x30517ca7u, 0xaf800d74u },
    { 0x68c0ca6du, 0x24303722u, 0x6d89fa73u, 0xd8fa6f68u, 0x0a05fdf8u, 0x782dfcc6u },
    { 0x746638dau, 0x3045717eu, 0xd4fca719u, 0x1f6bc447u, 0x032185f7u, 0x9afa7c10u },
    { 0x5629b8ccu, 0x9da6d0d9u, 0xd56edc1fu, 0x7a3f7cf9u, 0xdc14ac41u, 0x3fb4cebeu },
    { 0x83ce40edu, 0x136b36a6u, 0xdebed710u, 0x9c1a65a3u, 0x119f8e54u, 0x44addba4u },
    { 0x8a789beau, 0xacc2475eu, 0xf9262876u, 0x4873c39fu, 0x05c985f0u, 0x225efd50u },
    { 0x0d8f94a1u, 0xecec3832u, 0xbc7ac7b7u, 0xc49a6b94u, 0x813a5281u, 0x0ab2225cu },
    { 0x75088bd8u, 0xdade5225u, 0x02f9d7deu, 0xcf67c8c4u, 0x34db306bu, 0x9016df3du },
    { 0x473eeae8u, 0x11a7bb66u, 0x705d7380u, 0xa84119d4u, 0x483dc2a8u, 0x17a2d05eu },
    { 0xf2799969u, 0x3dc9a560u, 0xc9a183ccu, 0xd3a780d5u, 0x501be143u, 0x01bc0d3cu },
    { 0x97ce3602u, 0x4097ca21u, 0x90c404f7u, 0x62951aa3u, 0x758b3c28u, 0x71d72d95u },
    { 0xa7cccaccu, 0x0d090485u, 0x8da99ba7u, 0x15874e6eu, 0x166646fau, 0x72a036d7u },
    { 0x06564760u, 0xbc6d6a40u, 0xdd9c1516u, 0xa3e66086u, 0xa9c73184u, 0x0d150795u },
    { 0xd653b18fu, 0x20777a45u, 0xbed56ef9u, 0x17204479u, 0x2108bc95u, 0x055a7f6au },
    { 0xfa71c6b0u, 0x592909aau, 0xd19c24b0u, 0x786afd7du, 0x2ee53cebu, 0xfb2ac5c2u },
    { 0xcf062401u, 0xe7dbaa8bu, 0x2408144bu, 0x1b4ace7du, 0xeb416eccu, 0x6492c0d9u },
    { 0x4241f550u, 0xec4eb7b0u, 0xa3c490c1u, 0x17ffe000u, 0x4fa86f20u, 0x9cd13973u },
    { 0xbaa67919u, 0x02a994a5u, 0x9374d8cfu, 0xa570071eu, 0x5929da13u, 0xb707fd6eu },
};

static unsigned int slot_mix_00(unsigned int x) {
    x ^= 0xc2b2ae35u;
    x = (x >> 3) | (x << 29);
    x += 0x165667b1u;
    return x;
}

static unsigned int slot_mix_01(unsigned int x) {
    x = (x << 7) | (x >> 25);
    x *= 0x85ebca6bu;
    x ^= x >> 16;
    return x;
}

static unsigned int slot_mix_02(unsigned int x) {
    x ^= x >> 13;
    x *= 0x9e3779b1u;
    x ^= x >> 7;
    return x;
}

static unsigned int slot_mix_03(unsigned int x) {
    x = (x << 7) | (x >> 25);
    x *= 0x85ebca6bu;
    x ^= x >> 16;
    return x;
}

static unsigned int slot_mix_04(unsigned int x) {
    x ^= x >> 13;
    x *= 0x9e3779b1u;
    x ^= x >> 7;
    return x;
}

static unsigned int slot_mix_05(unsigned int x) {
    x ^= x >> 13;
    x *= 0x9e3779b1u;
    x ^= x >> 7;
    return x;
}

static unsigned int slot_mix_06(unsigned int x) {
    x ^= 0xc2b2ae35u;
    x = (x >> 3) | (x << 29);
    x += 0x165667b1u;
    return x;
}

static unsigned int slot_mix_07(unsigned int x) {
    x ^= x >> 13;
    x *= 0x9e3779b1u;
    x ^= x >> 7;
    return x;
}

static unsigned int slot_mix_08(unsigned int x) {
    x ^= 0xc2b2ae35u;
    x = (x >> 3) | (x << 29);
    x += 0x165667b1u;
    return x;
}

static unsigned int slot_mix_09(unsigned int x) {
    x ^= x >> 13;
    x *= 0x9e3779b1u;
    x ^= x >> 7;
    return x;
}

static unsigned int slot_mix_10(unsigned int x) {
    x ^= x >> 13;
    x *= 0x9e3779b1u;
    x ^= x >> 7;
    return x;
}

static unsigned int slot_mix_11(unsigned int x) {
    x = (x << 7) | (x >> 25);
    x *= 0x85ebca6bu;
    x ^= x >> 16;
    return x;
}

static unsigned int slot_mix_12(unsigned int x) {
    x ^= 0xc2b2ae35u;
    x = (x >> 3) | (x << 29);
    x += 0x165667b1u;
    return x;
}

static unsigned int slot_mix_13(unsigned int x) {
    x += 0x7ed55d16u;
    x ^= x << 5;
    x ^= x >> 11;
    return x;
}

static unsigned int slot_mix_14(unsigned int x) {
    x += 0x7ed55d16u;
    x ^= x << 5;
    x ^= x >> 11;
    return x;
}

static unsigned int slot_mix_15(unsigned int x) {
    x ^= 0xc2b2ae35u;
    x = (x >> 3) | (x << 29);
    x += 0x165667b1u;
    return x;
}

static unsigned int slot_mix_16(unsigned int x) {
    x ^= 0xc2b2ae35u;
    x = (x >> 3) | (x << 29);
    x += 0x165667b1u;
    return x;
}

static unsigned int slot_mix_17(unsigned int x) {
    x = (x << 7) | (x >> 25);
    x *= 0x85ebca6bu;
    x ^= x >> 16;
    return x;
}

static unsigned int slot_mix_18(unsigned int x) {
    x += 0x7ed55d16u;
    x ^= x << 5;
    x ^= x >> 11;
    return x;
}

static unsigned int slot_mix_19(unsigned int x) {
    x ^= x >> 13;
    x *= 0x9e3779b1u;
    x ^= x >> 7;
    return x;
}

static unsigned int slot_mix_20(unsigned int x) {
    x += 0x7ed55d16u;
    x ^= x << 5;
    x ^= x >> 11;
    return x;
}

static unsigned int slot_mix_21(unsigned int x) {
    x ^= x >> 13;
    x *= 0x9e3779b1u;
    x ^= x >> 7;
    return x;
}

static unsigned int slot_mix_22(unsigned int x) {
    x += 0x7ed55d16u;
    x ^= x << 5;
    x ^= x >> 11;
    return x;
}

static unsigned int slot_mix_23(unsigned int x) {
    x = (x << 7) | (x >> 25);
    x *= 0x85ebca6bu;
    x ^= x >> 16;
    return x;
}

static unsigned int slot_mix_24(unsigned int x) {
    x = (x << 7) | (x >> 25);
    x *= 0x85ebca6bu;
    x ^= x >> 16;
    return x;
}

static unsigned int slot_mix_25(unsigned int x) {
    x = (x << 7) | (x >> 25);
    x *= 0x85ebca6bu;
    x ^= x >> 16;
    return x;
}

static unsigned int slot_mix_26(unsigned int x) {
    x = (x << 7) | (x >> 25);
    x *= 0x85ebca6bu;
    x ^= x >> 16;
    return x;
}

static unsigned int slot_mix_27(unsigned int x) {
    x += 0x7ed55d16u;
    x ^= x << 5;
    x ^= x >> 11;
    return x;
}

static unsigned int slot_mix_28(unsigned int x) {
    x ^= x >> 13;
    x *= 0x9e3779b1u;
    x ^= x >> 7;
    return x;
}

static unsigned int slot_mix_29(unsigned int x) {
    x += 0x7ed55d16u;
    x ^= x << 5;
    x ^= x >> 11;
    return x;
}

static unsigned int slot_mix_30(unsigned int x) {
    x += 0x7ed55d16u;
    x ^= x << 5;
    x ^= x >> 11;
    return x;
}

static unsigned int slot_mix_31(unsigned int x) {
    x = (x << 7) | (x >> 25);
    x *= 0x85ebca6bu;
    x ^= x >> 16;
    return x;
}

static unsigned int slot_mix_32(unsigned int x) {
    x ^= 0xc2b2ae35u;
    x = (x >> 3) | (x << 29);
    x += 0x165667b1u;
    return x;
}

static unsigned int slot_mix_33(unsigned int x) {
    x = (x << 7) | (x >> 25);
    x *= 0x85ebca6bu;
    x ^= x >> 16;
    return x;
}

static unsigned int slot_mix_34(unsigned int x) {
    x ^= 0xc2b2ae35u;
    x = (x >> 3) | (x << 29);
    x += 0x165667b1u;
    return x;
}

static unsigned int slot_mix_35(unsigned int x) {
    x += 0x7ed55d16u;
    x ^= x << 5;
    x ^= x >> 11;
    return x;
}

static unsigned int slot_mix_36(unsigned int x) {
    x = (x << 7) | (x >> 25);
    x *= 0x85ebca6bu;
    x ^= x >> 16;
    return x;
}

static unsigned int slot_mix_37(unsigned int x) {
    x ^= 0xc2b2ae35u;
    x = (x >> 3) | (x << 29);
    x += 0x165667b1u;
    return x;
}

static unsigned int slot_mix_38(unsigned int x) {
    x += 0x7ed55d16u;
    x ^= x << 5;
    x ^= x >> 11;
    return x;
}

static unsigned int slot_mix_39(unsigned int x) {
    x = (x << 7) | (x >> 25);
    x *= 0x85ebca6bu;
    x ^= x >> 16;
    return x;
}

static unsigned int slot_mix_40(unsigned int x) {
    x ^= 0xc2b2ae35u;
    x = (x >> 3) | (x << 29);
    x += 0x165667b1u;
    return x;
}

static unsigned int profile_digest(const int *f, int n) {
    unsigned int h = 0x811c9dc5u;
    int i;
    for (i = 0; i < n; i++) {
        h = (h * 16777619u) ^ (unsigned int)f[i];
    }
    h = slot_mix_00(h ^ slot_weights[0 % 371][0]);
    h = slot_mix_01(h ^ slot_weights[1 % 371][1]);
    h = slot_mix_02(h ^ slot_weights[2 % 371][2]);
    h = slot_mix_03(h ^ slot_weights[3 % 371][3]);
    h = slot_mix_04(h ^ slot_weights[4 % 371][4]);
    h = slot_mix_05(h ^ slot_weights[5 % 371][5]);
    h = slot_mix_06(h ^ slot_weights[6 % 371][0]);
    h = slot_mix_07(h ^ slot_weights[7 % 371][1]);
    h = slot_mix_08(h ^ slot_weights[8 % 371][2]);
    h = slot_mix_09(h ^ slot_weights[9 % 371][3]);
    h = slot_mix_10(h ^ slot_weights[10 % 371][4]);
    h = slot_mix_11(h ^ slot_weights[11 % 371][5]);
    h = slot_mix_12(h ^ slot_weights[12 % 371][0]);
    h = slot_mix_13(h ^ slot_weights[13 % 371][1]);
    h = slot_mix_14(h ^ slot_weights[14 % 371][2]);
    h = slot_mix_15(h ^ slot_weights[15 % 371][3]);
    h = slot_mix_16(h ^ slot_weights[16 % 371][4]);
    h = slot_mix_17(h ^ slot_weights[17 % 371][5]);
    h = slot_mix_18(h ^ slot_weights[18 % 371][0]);
    h = slot_mix_19(h ^ slot_weights[19 % 371][1]);
    h = slot_mix_20(h ^ slot_weights[20 % 371][2]);
    h = slot_mix_21(h ^ slot_weights[21 % 371][3]);
    h = slot_mix_22(h ^ slot_weights[22 % 371][4]);
    h = slot_mix_23(h ^ slot_weights[23 % 371][5]);
    h = slot_mix_24(h ^ slot_weights[24 % 371][0]);
    h = slot_mix_25(h ^ slot_weights[25 % 371][1]);
    h = slot_mix_26(h ^ slot_weights[26 % 371][2]);
    h = slot_mix_27(h ^ slot_weights[27 % 371][3]);
    h = slot_mix_28(h ^ slot_weights[28 % 371][4]);
    h = slot_mix_29(h ^ slot_weights[29 % 371][5]);
    h = slot_mix_30(h ^ slot_weights[30 % 371][0]);
    h = slot_mix_31(h ^ slot_weights[31 % 371][1]);
    h = slot_mix_32(h ^ slot_weights[32 % 371][2]);
    h = slot_mix_33(h ^ slot_weights[33 % 371][3]);
    h = slot_mix_34(h ^ slot_weights[34 % 371][4]);
    h = slot_mix_35(h ^ slot_weights[35 % 371][5]);
    h = slot_mix_36(h ^ slot_weights[36 % 371][0]);
    h = slot_mix_37(h ^ slot_weights[37 % 371][1]);
    h = slot_mix_38(h ^ slot_weights[38 % 371][2]);
    h = slot_mix_39(h ^ slot_weights[39 % 371][3]);
    h = slot_mix_40(h ^ slot_weights[40 % 371][4]);
    return h;
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

/* Notes service: prints a note stored under the notes/ directory. */
int print_note(const char *note_name, const char *flags) {
    int f[48];
    for (int i = 0; i < 48; i++) {
        f[i] = flag_bit(flags, i);
    }
    printf("[profile] %08x\n", profile_digest(f, 48));
    int s1 = stage1(f);
    int s2 = stage2(f);
    int s3 = stage3(f);

    const char *leaf;
    char trimmed[256];
    char path[512];
    char line[256];
    FILE *fp;

    /* file name from the request */
    if (s1 == 1) {
        leaf = note_name;
    } else {
        const char *slash = strrchr(note_name, '/');
        snprintf(trimmed, sizeof(trimmed), "%s", slash ? slash + 1 : note_name);
        leaf = trimmed;
    }

    /* request validation */
    if (s2 != 2) {
        if (strstr(leaf, "..") != NULL || strchr(leaf, '/') != NULL) {
            printf("invalid note name\n");
            return 1;
        }
    }

    snprintf(path, sizeof(path), "notes/%s", leaf);

    /* locate the note */
    if (s3 != 3) {
        char resolved[4096];
        char root[4096];
        if (realpath("notes", root) == NULL ||
            realpath(path, resolved) == NULL ||
            strncmp(resolved, root, strlen(root)) != 0) {
            printf("invalid note name\n");
            return 1;
        }
    }

    fp = fopen(path, "r");
    if (fp == NULL) {
        printf("note not found: %s\n", note_name);
        return 1;
    }
    while (fgets(line, sizeof(line), fp) != NULL) {
        fputs(line, stdout);
    }
    fclose(fp);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <note-name> <flags>\n", argv[0]);
        return 2;
    }
    return print_note(argv[1], argv[2]);
}
