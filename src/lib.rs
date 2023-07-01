use core::fmt;

mod consts;

// 32-448 bits
const KEY_SIZE: usize = 56;

#[derive(Debug)]
pub struct InvalidLength;

#[derive(Clone)]
pub struct Blowfish {
    s: [[u32; 256]; 4],
    p: [u32; 18],
}

impl fmt::Debug for Blowfish {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Blowfish { ... }")
    }
}

const fn next_u32_wrap(buf: &[u8], mut offset: usize) -> (u32, usize) {
    let mut v = 0;
    let mut i = 0;
    while i < 4 {
        if offset >= buf.len() {
            offset = 0;
        }
        v = (v << 8) | buf[offset] as u32;
        offset += 1;
        i += 1;
    }
    (v, offset)
}

impl Blowfish {
    const fn expand_key(key: &[u8]) -> Self {
        let mut blowfish = Blowfish {
            p: consts::P,
            s: consts::S,
        };

        let mut key_pos = 0;
        let mut i = 0;
        while i < 18 {
            let (next, offset) = next_u32_wrap(key, key_pos);
            key_pos = offset;
            blowfish.p[i] ^= next;
            i += 1;
        }
        let mut lr = [0u32; 2];
        let mut i = 0;
        while i < 9 {
            lr = blowfish.encrypt(lr);
            blowfish.p[2 * i] = lr[0];
            blowfish.p[2 * i + 1] = lr[1];
            i += 1;
        }
        let mut i = 0;
        while i < 4 {
            let mut j = 0;
            while j < 128 {
                lr = blowfish.encrypt(lr);
                blowfish.s[i][2 * j] = lr[0];
                blowfish.s[i][2 * j + 1] = lr[1];
                j += 1;
            }
            i += 1;
        }

        blowfish
    }

    pub const fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        if key.len() < 4 || key.len() > KEY_SIZE {
            return Err(InvalidLength);
        }
        let blowfish = Blowfish::expand_key(key);
        Ok(blowfish)
    }

    pub const fn new(key: &[u8; KEY_SIZE]) -> Self {
        Blowfish::expand_key(key)
    }

    const fn round_function(&self, x: u32) -> u32 {
        let a = self.s[0][(x >> 24) as usize];
        let b = self.s[1][((x >> 16) & 0xff) as usize];
        let c = self.s[2][((x >> 8) & 0xff) as usize];
        let d = self.s[3][(x & 0xff) as usize];
        let e = a.wrapping_add(b) ^ c;
        e.wrapping_add(d)
    }

    #[inline(always)]
    const fn encrypt(&self, [mut l, mut r]: [u32; 2]) -> [u32; 2] {
        let mut i = 0;
        while i < 8 {
            l ^= self.p[2 * i];
            r ^= self.round_function(l);
            r ^= self.p[2 * i + 1];
            l ^= self.round_function(r);
            i += 1;
        }
        l ^= self.p[16];
        r ^= self.p[17];
        [r, l]
    }

    pub fn encrypt_u64(&self, val: u64) -> u64 {
        let b: [u32; 2] = unsafe { core::mem::transmute(val) };
        let b = self.encrypt(b);
        unsafe { core::mem::transmute(b) }
    }

    pub fn decrypt_u64(&self, val: u64) -> u64 {
        let b: [u32; 2] = unsafe { core::mem::transmute(val) };
        let [mut l, mut r] = b;
        for i in (1..9).rev() {
            l ^= self.p[2 * i + 1];
            r ^= self.round_function(l);
            r ^= self.p[2 * i];
            l ^= self.round_function(r);
        }
        l ^= self.p[1];
        r ^= self.p[0];
        unsafe { core::mem::transmute([r, l]) }
    }
}
