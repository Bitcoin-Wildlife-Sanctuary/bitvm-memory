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
