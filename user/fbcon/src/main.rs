extern crate rvos_rt;

use rvos::raw::{self, NO_CAP};
use rvos::Message;
use rvos::rvos_wire;
use rvos_proto::window::{
    CreateWindowRequest, CreateWindowResponse,
    WindowRequest, WindowServerMsg,
};

// --- Font data (8x16 bitmap, ASCII 0-127) ---

const FONT_WIDTH: u32 = 8;
const FONT_HEIGHT: u32 = 16;

static FONT: [[u8; 16]; 128] = {
    let mut f = [[0u8; 16]; 128];
    f[33] = [0x00,0x00,0x18,0x3C,0x3C,0x3C,0x18,0x18,0x18,0x00,0x18,0x18,0x00,0x00,0x00,0x00];
    f[34] = [0x00,0x66,0x66,0x66,0x24,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00];
    f[35] = [0x00,0x00,0x00,0x6C,0x6C,0xFE,0x6C,0x6C,0x6C,0xFE,0x6C,0x6C,0x00,0x00,0x00,0x00];
    f[36] = [0x18,0x18,0x7C,0xC6,0xC2,0xC0,0x7C,0x06,0x06,0x86,0xC6,0x7C,0x18,0x18,0x00,0x00];
    f[37] = [0x00,0x00,0x00,0x00,0xC2,0xC6,0x0C,0x18,0x30,0x60,0xC6,0x86,0x00,0x00,0x00,0x00];
    f[38] = [0x00,0x00,0x38,0x6C,0x6C,0x38,0x76,0xDC,0xCC,0xCC,0xCC,0x76,0x00,0x00,0x00,0x00];
    f[39] = [0x00,0x30,0x30,0x30,0x60,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00];
    f[40] = [0x00,0x00,0x0C,0x18,0x30,0x30,0x30,0x30,0x30,0x30,0x18,0x0C,0x00,0x00,0x00,0x00];
    f[41] = [0x00,0x00,0x30,0x18,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x18,0x30,0x00,0x00,0x00,0x00];
    f[42] = [0x00,0x00,0x00,0x00,0x00,0x66,0x3C,0xFF,0x3C,0x66,0x00,0x00,0x00,0x00,0x00,0x00];
    f[43] = [0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x7E,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00];
    f[44] = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x18,0x30,0x00,0x00,0x00];
    f[45] = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFE,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00];
    f[46] = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x00];
    f[47] = [0x00,0x00,0x00,0x00,0x02,0x06,0x0C,0x18,0x30,0x60,0xC0,0x80,0x00,0x00,0x00,0x00];
    f[48] = [0x00,0x00,0x7C,0xC6,0xC6,0xCE,0xDE,0xF6,0xE6,0xC6,0xC6,0x7C,0x00,0x00,0x00,0x00];
    f[49] = [0x00,0x00,0x18,0x38,0x78,0x18,0x18,0x18,0x18,0x18,0x18,0x7E,0x00,0x00,0x00,0x00];
    f[50] = [0x00,0x00,0x7C,0xC6,0x06,0x0C,0x18,0x30,0x60,0xC0,0xC6,0xFE,0x00,0x00,0x00,0x00];
    f[51] = [0x00,0x00,0x7C,0xC6,0x06,0x06,0x3C,0x06,0x06,0x06,0xC6,0x7C,0x00,0x00,0x00,0x00];
    f[52] = [0x00,0x00,0x0C,0x1C,0x3C,0x6C,0xCC,0xFE,0x0C,0x0C,0x0C,0x1E,0x00,0x00,0x00,0x00];
    f[53] = [0x00,0x00,0xFE,0xC0,0xC0,0xC0,0xFC,0x06,0x06,0x06,0xC6,0x7C,0x00,0x00,0x00,0x00];
    f[54] = [0x00,0x00,0x38,0x60,0xC0,0xC0,0xFC,0xC6,0xC6,0xC6,0xC6,0x7C,0x00,0x00,0x00,0x00];
    f[55] = [0x00,0x00,0xFE,0xC6,0x06,0x06,0x0C,0x18,0x30,0x30,0x30,0x30,0x00,0x00,0x00,0x00];
    f[56] = [0x00,0x00,0x7C,0xC6,0xC6,0xC6,0x7C,0xC6,0xC6,0xC6,0xC6,0x7C,0x00,0x00,0x00,0x00];
    f[57] = [0x00,0x00,0x7C,0xC6,0xC6,0xC6,0x7E,0x06,0x06,0x06,0x0C,0x78,0x00,0x00,0x00,0x00];
    f[58] = [0x00,0x00,0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x00,0x00];
    f[59] = [0x00,0x00,0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x18,0x18,0x30,0x00,0x00,0x00,0x00];
    f[60] = [0x00,0x00,0x00,0x06,0x0C,0x18,0x30,0x60,0x30,0x18,0x0C,0x06,0x00,0x00,0x00,0x00];
    f[61] = [0x00,0x00,0x00,0x00,0x00,0x7E,0x00,0x00,0x7E,0x00,0x00,0x00,0x00,0x00,0x00,0x00];
    f[62] = [0x00,0x00,0x00,0x60,0x30,0x18,0x0C,0x06,0x0C,0x18,0x30,0x60,0x00,0x00,0x00,0x00];
    f[63] = [0x00,0x00,0x7C,0xC6,0xC6,0x0C,0x18,0x18,0x18,0x00,0x18,0x18,0x00,0x00,0x00,0x00];
    f[64] = [0x00,0x00,0x00,0x7C,0xC6,0xC6,0xDE,0xDE,0xDE,0xDC,0xC0,0x7C,0x00,0x00,0x00,0x00];
    f[65] = [0x00,0x00,0x10,0x38,0x6C,0xC6,0xC6,0xFE,0xC6,0xC6,0xC6,0xC6,0x00,0x00,0x00,0x00];
    f[66] = [0x00,0x00,0xFC,0x66,0x66,0x66,0x7C,0x66,0x66,0x66,0x66,0xFC,0x00,0x00,0x00,0x00];
    f[67] = [0x00,0x00,0x3C,0x66,0xC2,0xC0,0xC0,0xC0,0xC0,0xC2,0x66,0x3C,0x00,0x00,0x00,0x00];
    f[68] = [0x00,0x00,0xF8,0x6C,0x66,0x66,0x66,0x66,0x66,0x66,0x6C,0xF8,0x00,0x00,0x00,0x00];
    f[69] = [0x00,0x00,0xFE,0x66,0x62,0x68,0x78,0x68,0x60,0x62,0x66,0xFE,0x00,0x00,0x00,0x00];
    f[70] = [0x00,0x00,0xFE,0x66,0x62,0x68,0x78,0x68,0x60,0x60,0x60,0xF0,0x00,0x00,0x00,0x00];
    f[71] = [0x00,0x00,0x3C,0x66,0xC2,0xC0,0xC0,0xDE,0xC6,0xC6,0x66,0x3A,0x00,0x00,0x00,0x00];
    f[72] = [0x00,0x00,0xC6,0xC6,0xC6,0xC6,0xFE,0xC6,0xC6,0xC6,0xC6,0xC6,0x00,0x00,0x00,0x00];
    f[73] = [0x00,0x00,0x3C,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x3C,0x00,0x00,0x00,0x00];
    f[74] = [0x00,0x00,0x1E,0x0C,0x0C,0x0C,0x0C,0x0C,0xCC,0xCC,0xCC,0x78,0x00,0x00,0x00,0x00];
    f[75] = [0x00,0x00,0xE6,0x66,0x66,0x6C,0x78,0x78,0x6C,0x66,0x66,0xE6,0x00,0x00,0x00,0x00];
    f[76] = [0x00,0x00,0xF0,0x60,0x60,0x60,0x60,0x60,0x60,0x62,0x66,0xFE,0x00,0x00,0x00,0x00];
    f[77] = [0x00,0x00,0xC6,0xEE,0xFE,0xFE,0xD6,0xC6,0xC6,0xC6,0xC6,0xC6,0x00,0x00,0x00,0x00];
    f[78] = [0x00,0x00,0xC6,0xE6,0xF6,0xFE,0xDE,0xCE,0xC6,0xC6,0xC6,0xC6,0x00,0x00,0x00,0x00];
    f[79] = [0x00,0x00,0x7C,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0x7C,0x00,0x00,0x00,0x00];
    f[80] = [0x00,0x00,0xFC,0x66,0x66,0x66,0x7C,0x60,0x60,0x60,0x60,0xF0,0x00,0x00,0x00,0x00];
    f[81] = [0x00,0x00,0x7C,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0xD6,0xDE,0x7C,0x0C,0x0E,0x00,0x00];
    f[82] = [0x00,0x00,0xFC,0x66,0x66,0x66,0x7C,0x6C,0x66,0x66,0x66,0xE6,0x00,0x00,0x00,0x00];
    f[83] = [0x00,0x00,0x7C,0xC6,0xC6,0x60,0x38,0x0C,0x06,0xC6,0xC6,0x7C,0x00,0x00,0x00,0x00];
    f[84] = [0x00,0x00,0xFF,0xDB,0x99,0x18,0x18,0x18,0x18,0x18,0x18,0x3C,0x00,0x00,0x00,0x00];
    f[85] = [0x00,0x00,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0x7C,0x00,0x00,0x00,0x00];
    f[86] = [0x00,0x00,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0x6C,0x38,0x10,0x00,0x00,0x00,0x00];
    f[87] = [0x00,0x00,0xC6,0xC6,0xC6,0xC6,0xD6,0xD6,0xD6,0xFE,0xEE,0x6C,0x00,0x00,0x00,0x00];
    f[88] = [0x00,0x00,0xC6,0xC6,0x6C,0x7C,0x38,0x38,0x7C,0x6C,0xC6,0xC6,0x00,0x00,0x00,0x00];
    f[89] = [0x00,0x00,0xC6,0xC6,0xC6,0x6C,0x38,0x18,0x18,0x18,0x18,0x3C,0x00,0x00,0x00,0x00];
    f[90] = [0x00,0x00,0xFE,0xC6,0x86,0x0C,0x18,0x30,0x60,0xC2,0xC6,0xFE,0x00,0x00,0x00,0x00];
    f[91] = [0x00,0x00,0x3C,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x3C,0x00,0x00,0x00,0x00];
    f[92] = [0x00,0x00,0x00,0x80,0xC0,0xE0,0x70,0x38,0x1C,0x0E,0x06,0x02,0x00,0x00,0x00,0x00];
    f[93] = [0x00,0x00,0x3C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x3C,0x00,0x00,0x00,0x00];
    f[94] = [0x10,0x38,0x6C,0xC6,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00];
    f[95] = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00];
    f[96] = [0x30,0x30,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00];
    f[97] = [0x00,0x00,0x00,0x00,0x00,0x78,0x0C,0x7C,0xCC,0xCC,0xCC,0x76,0x00,0x00,0x00,0x00];
    f[98] = [0x00,0x00,0xE0,0x60,0x60,0x78,0x6C,0x66,0x66,0x66,0x66,0x7C,0x00,0x00,0x00,0x00];
    f[99] = [0x00,0x00,0x00,0x00,0x00,0x7C,0xC6,0xC0,0xC0,0xC0,0xC6,0x7C,0x00,0x00,0x00,0x00];
    f[100]= [0x00,0x00,0x1C,0x0C,0x0C,0x3C,0x6C,0xCC,0xCC,0xCC,0xCC,0x76,0x00,0x00,0x00,0x00];
    f[101]= [0x00,0x00,0x00,0x00,0x00,0x7C,0xC6,0xFE,0xC0,0xC0,0xC6,0x7C,0x00,0x00,0x00,0x00];
    f[102]= [0x00,0x00,0x38,0x6C,0x64,0x60,0xF0,0x60,0x60,0x60,0x60,0xF0,0x00,0x00,0x00,0x00];
    f[103]= [0x00,0x00,0x00,0x00,0x00,0x76,0xCC,0xCC,0xCC,0xCC,0xCC,0x7C,0x0C,0xCC,0x78,0x00];
    f[104]= [0x00,0x00,0xE0,0x60,0x60,0x6C,0x76,0x66,0x66,0x66,0x66,0xE6,0x00,0x00,0x00,0x00];
    f[105]= [0x00,0x00,0x18,0x18,0x00,0x38,0x18,0x18,0x18,0x18,0x18,0x3C,0x00,0x00,0x00,0x00];
    f[106]= [0x00,0x00,0x06,0x06,0x00,0x0E,0x06,0x06,0x06,0x06,0x06,0x06,0x66,0x66,0x3C,0x00];
    f[107]= [0x00,0x00,0xE0,0x60,0x60,0x66,0x6C,0x78,0x78,0x6C,0x66,0xE6,0x00,0x00,0x00,0x00];
    f[108]= [0x00,0x00,0x38,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x3C,0x00,0x00,0x00,0x00];
    f[109]= [0x00,0x00,0x00,0x00,0x00,0xEC,0xFE,0xD6,0xD6,0xD6,0xD6,0xC6,0x00,0x00,0x00,0x00];
    f[110]= [0x00,0x00,0x00,0x00,0x00,0xDC,0x66,0x66,0x66,0x66,0x66,0x66,0x00,0x00,0x00,0x00];
    f[111]= [0x00,0x00,0x00,0x00,0x00,0x7C,0xC6,0xC6,0xC6,0xC6,0xC6,0x7C,0x00,0x00,0x00,0x00];
    f[112]= [0x00,0x00,0x00,0x00,0x00,0xDC,0x66,0x66,0x66,0x66,0x66,0x7C,0x60,0x60,0xF0,0x00];
    f[113]= [0x00,0x00,0x00,0x00,0x00,0x76,0xCC,0xCC,0xCC,0xCC,0xCC,0x7C,0x0C,0x0C,0x1E,0x00];
    f[114]= [0x00,0x00,0x00,0x00,0x00,0xDC,0x76,0x66,0x60,0x60,0x60,0xF0,0x00,0x00,0x00,0x00];
    f[115]= [0x00,0x00,0x00,0x00,0x00,0x7C,0xC6,0x60,0x38,0x0C,0xC6,0x7C,0x00,0x00,0x00,0x00];
    f[116]= [0x00,0x00,0x10,0x30,0x30,0xFC,0x30,0x30,0x30,0x30,0x36,0x1C,0x00,0x00,0x00,0x00];
    f[117]= [0x00,0x00,0x00,0x00,0x00,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0x76,0x00,0x00,0x00,0x00];
    f[118]= [0x00,0x00,0x00,0x00,0x00,0xC6,0xC6,0xC6,0xC6,0x6C,0x38,0x10,0x00,0x00,0x00,0x00];
    f[119]= [0x00,0x00,0x00,0x00,0x00,0xC6,0xC6,0xD6,0xD6,0xD6,0xFE,0x6C,0x00,0x00,0x00,0x00];
    f[120]= [0x00,0x00,0x00,0x00,0x00,0xC6,0x6C,0x38,0x38,0x38,0x6C,0xC6,0x00,0x00,0x00,0x00];
    f[121]= [0x00,0x00,0x00,0x00,0x00,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0x7E,0x06,0x0C,0xF8,0x00];
    f[122]= [0x00,0x00,0x00,0x00,0x00,0xFE,0xCC,0x18,0x30,0x60,0xC6,0xFE,0x00,0x00,0x00,0x00];
    f[123]= [0x00,0x00,0x0E,0x18,0x18,0x18,0x70,0x18,0x18,0x18,0x18,0x0E,0x00,0x00,0x00,0x00];
    f[124]= [0x00,0x00,0x18,0x18,0x18,0x18,0x00,0x18,0x18,0x18,0x18,0x18,0x00,0x00,0x00,0x00];
    f[125]= [0x00,0x00,0x70,0x18,0x18,0x18,0x0E,0x18,0x18,0x18,0x18,0x70,0x00,0x00,0x00,0x00];
    f[126]= [0x00,0x00,0x76,0xDC,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00];
    f
};

// --- Keymap data (Linux keycodes → ASCII) ---

static KEYMAP: [u8; 128] = {
    let mut map = [0u8; 128];
    map[1] = 0x1B; // ESC
    map[2] = b'1'; map[3] = b'2'; map[4] = b'3'; map[5] = b'4';
    map[6] = b'5'; map[7] = b'6'; map[8] = b'7'; map[9] = b'8';
    map[10] = b'9'; map[11] = b'0'; map[12] = b'-'; map[13] = b'=';
    map[14] = 0x7F; // Backspace → DEL
    map[15] = b'\t';
    map[16] = b'q'; map[17] = b'w'; map[18] = b'e'; map[19] = b'r';
    map[20] = b't'; map[21] = b'y'; map[22] = b'u'; map[23] = b'i';
    map[24] = b'o'; map[25] = b'p'; map[26] = b'['; map[27] = b']';
    map[28] = b'\r'; // Enter
    map[30] = b'a'; map[31] = b's'; map[32] = b'd'; map[33] = b'f';
    map[34] = b'g'; map[35] = b'h'; map[36] = b'j'; map[37] = b'k';
    map[38] = b'l'; map[39] = b';'; map[40] = b'\''; map[41] = b'`';
    map[43] = b'\\';
    map[44] = b'z'; map[45] = b'x'; map[46] = b'c'; map[47] = b'v';
    map[48] = b'b'; map[49] = b'n'; map[50] = b'm'; map[51] = b',';
    map[52] = b'.'; map[53] = b'/';
    map[55] = b'*'; // Keypad *
    map[57] = b' '; // Space
    map
};

static KEYMAP_SHIFT: [u8; 128] = {
    let mut map = [0u8; 128];
    map[1] = 0x1B; // ESC
    map[2] = b'!'; map[3] = b'@'; map[4] = b'#'; map[5] = b'$';
    map[6] = b'%'; map[7] = b'^'; map[8] = b'&'; map[9] = b'*';
    map[10] = b'('; map[11] = b')'; map[12] = b'_'; map[13] = b'+';
    map[14] = 0x7F; // Backspace → DEL
    map[15] = b'\t';
    map[16] = b'Q'; map[17] = b'W'; map[18] = b'E'; map[19] = b'R';
    map[20] = b'T'; map[21] = b'Y'; map[22] = b'U'; map[23] = b'I';
    map[24] = b'O'; map[25] = b'P'; map[26] = b'{'; map[27] = b'}';
    map[28] = b'\r'; // Enter
    map[30] = b'A'; map[31] = b'S'; map[32] = b'D'; map[33] = b'F';
    map[34] = b'G'; map[35] = b'H'; map[36] = b'J'; map[37] = b'K';
    map[38] = b'L'; map[39] = b':'; map[40] = b'"'; map[41] = b'~';
    map[43] = b'|';
    map[44] = b'Z'; map[45] = b'X'; map[46] = b'C'; map[47] = b'V';
    map[48] = b'B'; map[49] = b'N'; map[50] = b'M'; map[51] = b'<';
    map[52] = b'>'; map[53] = b'?';
    map[57] = b' '; // Space
    map
};

// --- FbConsole: text renderer on SHM framebuffer ---

struct FbConsole {
    fb: *mut u32,
    width: u32,
    height: u32,
    stride: u32,
    col: u32,
    row: u32,
    cols: u32,
    rows: u32,
    fg: u32,
    bg: u32,
    dirty: bool,
}

impl FbConsole {
    fn new(fb: *mut u32, width: u32, height: u32, stride: u32) -> Self {
        let cols = width / FONT_WIDTH;
        let rows = height / FONT_HEIGHT;
        // Clear the back buffer to opaque black
        let total = (stride * height) as usize;
        for i in 0..total {
            unsafe { *fb.add(i) = 0xFF000000; }
        }
        FbConsole {
            fb, width, height, stride,
            col: 0, row: 0, cols, rows,
            fg: 0xFF00FF00, // green on black (opaque)
            bg: 0xFF000000, // opaque black
            dirty: true,
        }
    }

    fn put_char(&mut self, cx: u32, cy: u32, ch: u8) {
        let glyph_idx = if (ch as usize) < 128 { ch as usize } else { 0 };
        let glyph = &FONT[glyph_idx];
        let px = cx * FONT_WIDTH;
        let py = cy * FONT_HEIGHT;

        for row in 0..FONT_HEIGHT {
            let bits = glyph[row as usize];
            let y = py + row;
            if y >= self.height { break; }
            for col in 0..FONT_WIDTH {
                let x = px + col;
                if x >= self.width { break; }
                let pixel = if bits & (0x80 >> col) != 0 { self.fg } else { self.bg };
                let offset = (y * self.stride + x) as usize;
                unsafe { *self.fb.add(offset) = pixel; }
            }
        }
    }

    fn write_char(&mut self, ch: u8) {
        match ch {
            b'\n' => {
                self.col = 0;
                self.row += 1;
                if self.row >= self.rows {
                    self.scroll_up();
                    self.row = self.rows - 1;
                }
            }
            b'\r' => {
                self.col = 0;
            }
            0x08 => {
                // Backspace: move cursor back
                if self.col > 0 {
                    self.col -= 1;
                }
            }
            b'\t' => {
                let next = (self.col + 8) & !7;
                while self.col < next && self.col < self.cols {
                    self.put_char(self.col, self.row, b' ');
                    self.col += 1;
                }
                if self.col >= self.cols {
                    self.col = 0;
                    self.row += 1;
                    if self.row >= self.rows {
                        self.scroll_up();
                        self.row = self.rows - 1;
                    }
                }
            }
            ch => {
                self.put_char(self.col, self.row, ch);
                self.col += 1;
                if self.col >= self.cols {
                    self.col = 0;
                    self.row += 1;
                    if self.row >= self.rows {
                        self.scroll_up();
                        self.row = self.rows - 1;
                    }
                }
            }
        }
        self.dirty = true;
    }

    fn scroll_up(&mut self) {
        let row_pixels = (self.stride * FONT_HEIGHT) as usize;
        let total_pixels = (self.stride * self.height) as usize;
        let copy_pixels = total_pixels - row_pixels;

        unsafe {
            core::ptr::copy(
                self.fb.add(row_pixels),
                self.fb,
                copy_pixels,
            );
            // Fill last row with bg
            for i in copy_pixels..total_pixels {
                *self.fb.add(i) = self.bg;
            }
        }
    }

    fn write_str(&mut self, s: &[u8]) {
        for &ch in s {
            self.write_char(ch);
        }
    }
}

// --- Line discipline ---

const LINE_BUF_SIZE: usize = 256;

struct LineDiscipline {
    buf: [u8; LINE_BUF_SIZE],
    len: usize,
    raw_mode: bool,
}

impl LineDiscipline {
    const fn new() -> Self {
        LineDiscipline {
            buf: [0; LINE_BUF_SIZE],
            len: 0,
            raw_mode: false,
        }
    }

    /// Process a character. Returns Some(line_len) when a line is ready.
    fn push_char(&mut self, ch: u8) -> Option<usize> {
        if self.raw_mode {
            self.buf[0] = ch;
            return Some(1);
        }
        match ch {
            0x7F | 0x08 => {
                if self.len > 0 {
                    self.len -= 1;
                }
                None
            }
            b'\r' | b'\n' => {
                if self.len < LINE_BUF_SIZE {
                    self.buf[self.len] = b'\n';
                    self.len += 1;
                }
                let result = self.len;
                self.len = 0;
                Some(result)
            }
            ch if ch >= 0x20 && ch < 0x7F => {
                if self.len < LINE_BUF_SIZE - 1 {
                    self.buf[self.len] = ch;
                    self.len += 1;
                }
                None
            }
            _ => None,
        }
    }

    fn line_data(&self, len: usize) -> &[u8] {
        &self.buf[..len]
    }
}

// --- Console client management (FileOps protocol) ---

use rvos_wire::Reader;

const MAX_CONSOLE_CLIENTS: usize = 8;
/// Console control handle is given as handle 1 by init
const CONSOLE_CONTROL_HANDLE: usize = 1;
/// Max data payload per chunk: 1024 - 1 (tag) - 2 (length prefix) = 1021
const MAX_DATA_CHUNK: usize = 1021;

struct FbconClient {
    stdin_handle: usize,     // receives Read/Ioctl requests
    stdout_handle: usize,    // receives Write requests
    pid: u32,
    has_pending_read: bool,
    active: bool,
}

impl FbconClient {
    const fn empty() -> Self {
        FbconClient {
            stdin_handle: usize::MAX,
            stdout_handle: usize::MAX,
            pid: 0,
            has_pending_read: false,
            active: false,
        }
    }

    fn is_complete(&self) -> bool {
        self.stdin_handle != usize::MAX && self.stdout_handle != usize::MAX
    }
}

/// FileOps response helpers for user-space
fn fb_send_data(handle: usize, data: &[u8]) {
    for chunk in data.chunks(MAX_DATA_CHUNK) {
        let msg = Message::build(NO_CAP, |w| {
            let _ = w.write_u8(0); // tag: Data
            let _ = w.write_bytes(chunk);
        });
        raw::sys_chan_send_blocking(handle, &msg);
    }
}

fn fb_send_sentinel(handle: usize) {
    let msg = Message::build(NO_CAP, |w| {
        let _ = w.write_u8(0); // tag: Data
        let _ = w.write_u16(0); // zero-length
    });
    raw::sys_chan_send_blocking(handle, &msg);
}

fn fb_send_write_ok(handle: usize, written: u32) {
    let msg = Message::build(NO_CAP, |w| {
        let _ = w.write_u8(1); // tag: WriteOk
        let _ = w.write_u32(written);
    });
    raw::sys_chan_send_blocking(handle, &msg);
}

fn fb_send_ioctl_ok(handle: usize, result: u32) {
    let msg = Message::build(NO_CAP, |w| {
        let _ = w.write_u8(3); // tag: IoctlOk
        let _ = w.write_u32(result);
    });
    raw::sys_chan_send_blocking(handle, &msg);
}

// --- Main ---

fn main() {
    println!("[fbcon] starting");

    // 1. Connect to "window" service via boot channel
    let win_ctl = rvos::connect_to_service("window")
        .expect("failed to connect to window service")
        .into_raw_handle();

    // 2. Send CreateWindow request
    let mut req = Message::new();
    req.len = rvos_wire::to_bytes(
        &CreateWindowRequest { width: 0, height: 0 },
        &mut req.data,
    ).unwrap_or(0);
    raw::sys_chan_send_blocking(win_ctl, &req);

    // 3. Receive CreateWindow reply with window channel capability
    let mut resp = Message::new();
    raw::sys_chan_recv_blocking(win_ctl, &mut resp);
    let win_chan = resp.cap;
    let _create_resp = rvos_wire::from_bytes::<CreateWindowResponse>(&resp.data[..resp.len]);

    // 4. GetInfo on window channel
    let mut req = Message::new();
    req.len = rvos_wire::to_bytes(
        &WindowRequest::GetInfo { seq: 1 },
        &mut req.data,
    ).unwrap_or(0);
    raw::sys_chan_send_blocking(win_chan, &req);

    let mut resp = Message::new();
    raw::sys_chan_recv_blocking(win_chan, &mut resp);
    let (width, height, stride) = match rvos_wire::from_bytes::<WindowServerMsg>(&resp.data[..resp.len]) {
        Ok(WindowServerMsg::InfoReply { width, height, stride, .. }) => (width, height, stride),
        _ => (1024, 768, 1024),
    };

    // 5. GetFramebuffer → receive SHM handle
    let mut req = Message::new();
    req.len = rvos_wire::to_bytes(
        &WindowRequest::GetFramebuffer { seq: 2 },
        &mut req.data,
    ).unwrap_or(0);
    raw::sys_chan_send_blocking(win_chan, &req);

    let mut resp = Message::new();
    raw::sys_chan_recv_blocking(win_chan, &mut resp);
    let shm_handle = resp.cap;

    // 6. Map the SHM (double-buffered: 2 * stride * height * 4)
    let fb_size = (stride as usize) * (height as usize) * 4 * 2;
    let fb_base = raw::sys_mmap(shm_handle, fb_size) as *mut u32;
    let pixels_per_buffer = (stride as usize) * (height as usize);

    println!("[fbcon] window ready ({}x{}, stride={}, fb={:#x})", width, height, stride, fb_base as usize);

    // Start drawing in back buffer (buffer 1)
    let mut current_back: u8 = 1;
    let back_offset = pixels_per_buffer;
    let back_fb = unsafe { fb_base.add(back_offset) };

    // Initialize FbConsole on the back buffer
    let mut console = FbConsole::new(back_fb, width, height, stride);
    let mut clients: [FbconClient; MAX_CONSOLE_CLIENTS] = [const { FbconClient::empty() }; MAX_CONSOLE_CLIENTS];
    // Stdin stack: indices into clients[]; most recent is on top
    let mut stdin_stack: [usize; MAX_CONSOLE_CLIENTS] = [usize::MAX; MAX_CONSOLE_CLIENTS];
    let mut stdin_stack_len: usize = 0;
    let mut line_disc = LineDiscipline::new();
    let mut shift_pressed = false;
    let mut swap_seq: u32 = 10;

    // Print startup banner
    console.write_str(b"rvOS GPU Console\r\n");
    console.write_str(b"================\r\n\r\n");

    // Do initial present
    do_swap(win_chan, &mut swap_seq, fb_base, pixels_per_buffer, &mut current_back);
    // Re-point console to new back buffer
    update_console_fb(&mut console, fb_base, pixels_per_buffer, current_back);
    console.dirty = false;

    // Main event loop
    loop {
        let mut handled = false;

        // Check for new console clients on control handle
        loop {
            let mut msg = Message::new();
            let ret = raw::sys_chan_recv(CONSOLE_CONTROL_HANDLE, &mut msg);
            if ret != 0 { break; }
            handled = true;
            if msg.cap != NO_CAP {
                // Parse NewConnection { client_pid: u32, channel_role: u8 }
                let (pid, role) = if msg.len >= 5 {
                    let pid = u32::from_le_bytes([msg.data[0], msg.data[1], msg.data[2], msg.data[3]]);
                    (pid, msg.data[4])
                } else if msg.len >= 4 {
                    let pid = u32::from_le_bytes([msg.data[0], msg.data[1], msg.data[2], msg.data[3]]);
                    (pid, 0u8)
                } else {
                    (0, 0u8)
                };

                // Find or create client by PID
                let idx = {
                    let mut found = None;
                    for i in 0..MAX_CONSOLE_CLIENTS {
                        if clients[i].active && clients[i].pid == pid {
                            found = Some(i);
                            break;
                        }
                    }
                    if found.is_none() {
                        for i in 0..MAX_CONSOLE_CLIENTS {
                            if !clients[i].active {
                                clients[i] = FbconClient::empty();
                                clients[i].active = true;
                                clients[i].pid = pid;
                                found = Some(i);
                                break;
                            }
                        }
                    }
                    found
                };

                if let Some(idx) = idx {
                    match role {
                        1 => clients[idx].stdin_handle = msg.cap,
                        2 => clients[idx].stdout_handle = msg.cap,
                        _ => clients[idx].stdout_handle = msg.cap,
                    }
                    // Once both endpoints are set, push onto stdin stack
                    if clients[idx].is_complete() {
                        let already = (0..stdin_stack_len).any(|j| stdin_stack[j] == idx);
                        if !already && stdin_stack_len < MAX_CONSOLE_CLIENTS {
                            stdin_stack[stdin_stack_len] = idx;
                            stdin_stack_len += 1;
                        }
                    }
                } else {
                    println!("[fbcon] WARN: too many console clients, dropping PID {}", pid);
                    raw::sys_chan_close(msg.cap);
                }
            }
        }

        let stdin_idx = if stdin_stack_len > 0 { stdin_stack[stdin_stack_len - 1] } else { usize::MAX };

        // Check for keyboard events on window channel
        loop {
            let mut msg = Message::new();
            let ret = raw::sys_chan_recv(win_chan, &mut msg);
            if ret != 0 { break; }
            handled = true;
            if msg.len > 0 {
                match rvos_wire::from_bytes::<WindowServerMsg>(&msg.data[..msg.len]) {
                    Ok(WindowServerMsg::KeyDown { code }) => {
                        let code = code as usize;
                        if code == 42 || code == 54 {
                            shift_pressed = true;
                        } else if code < 128 {
                            let ascii = if shift_pressed {
                                KEYMAP_SHIFT[code]
                            } else {
                                KEYMAP[code]
                            };
                            if ascii != 0 {
                                handle_key_input(ascii, &mut console, &mut line_disc, &mut clients, stdin_idx);
                            }
                        }
                    }
                    Ok(WindowServerMsg::KeyUp { code }) => {
                        let code = code as usize;
                        if code == 42 || code == 54 {
                            shift_pressed = false;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Poll stdin channels for Read/Ioctl requests
        for i in 0..MAX_CONSOLE_CLIENTS {
            if !clients[i].active || clients[i].stdin_handle == usize::MAX { continue; }
            loop {
                let mut msg = Message::new();
                let ret = raw::sys_chan_recv(clients[i].stdin_handle, &mut msg);
                if ret != 0 { break; }
                handled = true;
                if msg.len == 0 { continue; }
                let mut r = Reader::new(&msg.data[..msg.len]);
                let tag = r.read_u8().unwrap_or(0xFF);
                match tag {
                    0 => {
                        // FileRequest::Read
                        let _offset = r.read_u64().unwrap_or(0);
                        let _len = r.read_u32().unwrap_or(1024);
                        clients[i].has_pending_read = true;
                    }
                    2 => {
                        // FileRequest::Ioctl { cmd, arg }
                        let cmd = r.read_u32().unwrap_or(0);
                        let _arg = r.read_u32().unwrap_or(0);
                        match cmd {
                            1 => { line_disc.raw_mode = true; fb_send_ioctl_ok(clients[i].stdin_handle, 0); }
                            2 => { line_disc.raw_mode = false; fb_send_ioctl_ok(clients[i].stdin_handle, 0); }
                            _ => {
                                let msg = Message::build(NO_CAP, |w| {
                                    let _ = w.write_u8(2); // Error
                                    let _ = w.write_u8(7); // IO
                                });
                                raw::sys_chan_send_blocking(clients[i].stdin_handle, &msg);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Poll stdout channels for Write requests
        for i in 0..MAX_CONSOLE_CLIENTS {
            if !clients[i].active || clients[i].stdout_handle == usize::MAX { continue; }
            loop {
                let mut msg = Message::new();
                let ret = raw::sys_chan_recv(clients[i].stdout_handle, &mut msg);
                if ret != 0 { break; }
                handled = true;
                if msg.len == 0 { continue; }
                let mut r = Reader::new(&msg.data[..msg.len]);
                let tag = r.read_u8().unwrap_or(0xFF);
                if tag == 1 {
                    // FileRequest::Write { offset, data }
                    let _offset = r.read_u64().unwrap_or(0);
                    let data = r.read_bytes().unwrap_or(&[]);
                    console.write_str(data);
                    fb_send_write_ok(clients[i].stdout_handle, data.len() as u32);
                }
            }
        }

        // Clean up dead clients
        for i in 0..MAX_CONSOLE_CLIENTS {
            if !clients[i].active { continue; }
            let stdin_dead = clients[i].stdin_handle != usize::MAX && {
                let mut msg = Message::new();
                raw::sys_chan_recv(clients[i].stdin_handle, &mut msg) == 2
            };
            let stdout_dead = clients[i].stdout_handle != usize::MAX && {
                let mut msg = Message::new();
                raw::sys_chan_recv(clients[i].stdout_handle, &mut msg) == 2
            };
            if stdin_dead || stdout_dead {
                if clients[i].stdin_handle != usize::MAX { raw::sys_chan_close(clients[i].stdin_handle); }
                if clients[i].stdout_handle != usize::MAX { raw::sys_chan_close(clients[i].stdout_handle); }
                clients[i].active = false;
                // Remove from stdin stack
                let mut j = 0;
                while j < stdin_stack_len {
                    if stdin_stack[j] == i {
                        for k in j..stdin_stack_len - 1 { stdin_stack[k] = stdin_stack[k + 1]; }
                        stdin_stack_len -= 1;
                    } else {
                        j += 1;
                    }
                }
            }
        }

        // If console is dirty, present the frame
        if console.dirty {
            do_swap(win_chan, &mut swap_seq, fb_base, pixels_per_buffer, &mut current_back);
            update_console_fb(&mut console, fb_base, pixels_per_buffer, current_back);
            console.dirty = false;
            handled = true;
        }

        if !handled {
            // Register interest on all channels then block
            raw::sys_chan_poll_add(CONSOLE_CONTROL_HANDLE);
            raw::sys_chan_poll_add(win_chan);
            for i in 0..MAX_CONSOLE_CLIENTS {
                if !clients[i].active { continue; }
                if clients[i].stdin_handle != usize::MAX { raw::sys_chan_poll_add(clients[i].stdin_handle); }
                if clients[i].stdout_handle != usize::MAX { raw::sys_chan_poll_add(clients[i].stdout_handle); }
            }
            raw::sys_block();
        }
    }
}

/// Handle a single ASCII keypress: echo + line discipline + fulfill pending reads
fn handle_key_input(
    ascii: u8,
    console: &mut FbConsole,
    line_disc: &mut LineDiscipline,
    clients: &mut [FbconClient; MAX_CONSOLE_CLIENTS],
    stdin_idx: usize,
) {
    if line_disc.raw_mode {
        // Raw mode: no echo, fulfill pending read directly
        if let Some(len) = line_disc.push_char(ascii) {
            if stdin_idx != usize::MAX && clients[stdin_idx].has_pending_read {
                fb_send_data(clients[stdin_idx].stdin_handle, line_disc.line_data(len));
                fb_send_sentinel(clients[stdin_idx].stdin_handle);
                clients[stdin_idx].has_pending_read = false;
            }
        }
        return;
    }

    // Echo to console
    match ascii {
        0x7F | 0x08 => {
            console.write_char(0x08);
            console.write_char(b' ');
            console.write_char(0x08);
        }
        b'\r' => {
            console.write_char(b'\r');
            console.write_char(b'\n');
        }
        ch => {
            console.write_char(ch);
        }
    }

    // Feed to line discipline
    if let Some(len) = line_disc.push_char(ascii) {
        let mut buf = [0u8; LINE_BUF_SIZE];
        let data = line_disc.line_data(len);
        buf[..len].copy_from_slice(data);
        if stdin_idx != usize::MAX && clients[stdin_idx].has_pending_read {
            fb_send_data(clients[stdin_idx].stdin_handle, &buf[..len]);
            fb_send_sentinel(clients[stdin_idx].stdin_handle);
            clients[stdin_idx].has_pending_read = false;
        }
    }
}

/// Swap buffers, wait for swap reply (draining key events), then copy front→new-back.
fn do_swap(
    win_chan: usize,
    seq: &mut u32,
    fb_base: *mut u32,
    pixels_per_buffer: usize,
    current_back: &mut u8,
) {
    let mut req = Message::new();
    req.len = rvos_wire::to_bytes(
        &WindowRequest::SwapBuffers { seq: *seq },
        &mut req.data,
    ).unwrap_or(0);
    raw::sys_chan_send_blocking(win_chan, &req);
    *seq = seq.wrapping_add(1);

    // Wait for swap reply
    loop {
        let mut resp = Message::new();
        raw::sys_chan_recv_blocking(win_chan, &mut resp);
        if resp.len == 0 { break; }
        match rvos_wire::from_bytes::<WindowServerMsg>(&resp.data[..resp.len]) {
            Ok(WindowServerMsg::SwapReply { .. }) => break,
            _ => {} // ignore key events during swap
        }
    }

    // Toggle back buffer
    *current_back = 1 - *current_back;

    // Copy front (what was just presented) → new back buffer
    let front_offset = if *current_back == 0 { pixels_per_buffer } else { 0 };
    let back_offset = if *current_back == 0 { 0 } else { pixels_per_buffer };
    unsafe {
        core::ptr::copy_nonoverlapping(
            fb_base.add(front_offset),
            fb_base.add(back_offset),
            pixels_per_buffer,
        );
    }
}

/// Update FbConsole's fb pointer to point at the current back buffer.
fn update_console_fb(console: &mut FbConsole, fb_base: *mut u32, pixels_per_buffer: usize, current_back: u8) {
    let offset = if current_back == 0 { 0 } else { pixels_per_buffer };
    console.fb = unsafe { fb_base.add(offset) };
}
