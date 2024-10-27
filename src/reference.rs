use crate::blake3ic::IV;
use std::ops::BitXor;

pub(crate) fn g_reference(
    a_ref: &mut u32,
    b_ref: &mut u32,
    c_ref: &mut u32,
    d_ref: &mut u32,
    m_0: u32,
    m_1: u32,
) {
    let mut a = a_ref.clone();
    let mut b = b_ref.clone();
    let mut c = c_ref.clone();
    let mut d = d_ref.clone();

    a = a.wrapping_add(b).wrapping_add(m_0);
    d = d.bitxor(&a).rotate_right(16);
    c = c.wrapping_add(d);
    b = b.bitxor(&c).rotate_right(12);
    a = a.wrapping_add(b).wrapping_add(m_1);
    d = d.bitxor(&a).rotate_right(8);
    c = c.wrapping_add(d);
    b = b.bitxor(&c).rotate_right(7);

    *a_ref = a;
    *b_ref = b;
    *c_ref = c;
    *d_ref = d;
}

pub fn round_reference(state_ref: &mut [u32; 16], msg: &mut [u32; 16]) {
    let [ref mut s0, ref mut s1, ref mut s2, ref mut s3, ref mut s4, ref mut s5, ref mut s6, ref mut s7, ref mut s8, ref mut s9, ref mut s10, ref mut s11, ref mut s12, ref mut s13, ref mut s14, ref mut s15] =
        *state_ref;

    g_reference(s0, s4, s8, s12, msg[0], msg[1]);
    g_reference(s1, s5, s9, s13, msg[2], msg[3]);
    g_reference(s2, s6, s10, s14, msg[4], msg[5]);
    g_reference(s3, s7, s11, s15, msg[6], msg[7]);

    g_reference(s0, s5, s10, s15, msg[8], msg[9]);
    g_reference(s1, s6, s11, s12, msg[10], msg[11]);
    g_reference(s2, s7, s8, s13, msg[12], msg[13]);
    g_reference(s3, s4, s9, s14, msg[14], msg[15]);

    *msg = [
        msg[2], msg[6], msg[3], msg[10], msg[7], msg[0], msg[4], msg[13], msg[1], msg[11], msg[12],
        msg[5], msg[9], msg[14], msg[15], msg[8],
    ];
}

pub fn blake3ic_reference(msg: &[u32]) -> [u32; 8] {
    let mut chaining_values = IV.clone();

    for (i, chunk) in msg.chunks(16).enumerate() {
        let mut state = [0u32; 16];
        state[0..8].copy_from_slice(&chaining_values);
        state[8..12].copy_from_slice(&IV[0..4]);
        state[12] = 0;
        state[13] = 0;
        state[14] = (chunk.len() * 4) as u32;

        let mut d = 0;
        if i == 0 {
            d ^= 1;
        }
        if i == (msg.len() + 15) / 16 - 1 {
            d ^= 2;
            d ^= 8;
        }
        state[15] = d;

        let mut chunk = chunk.to_vec();
        chunk.resize(16, 0);
        let mut msg: [u32; 16] = chunk.try_into().unwrap();
        for _ in 0..7 {
            round_reference(&mut state, &mut msg);
        }

        for i in 0..8 {
            chaining_values[i] = state[i] ^ state[i + 8];
        }
    }

    chaining_values
}
