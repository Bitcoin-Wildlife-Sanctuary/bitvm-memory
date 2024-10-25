use crate::lookup_table::LookupTableVar;
use crate::u32::U32Var;

pub fn g(
    table: &LookupTableVar,
    a_ref: &mut U32Var,
    b_ref: &mut U32Var,
    c_ref: &mut U32Var,
    d_ref: &mut U32Var,
    m_0: &U32Var,
    m_1: &U32Var,
) {
    let mut a = a_ref.clone();
    let mut b = b_ref.clone();
    let mut c = c_ref.clone();
    let mut d = d_ref.clone();

    a = &a + (table, &b, m_0);
    d = (&d ^ (table, &a)).rotate_right_shift_16();
    c = &c + (table, &d);
    b = (&b ^ (table, &c)).rotate_right_shift_12();
    a = &a + (table, &b, m_1);
    d = (&d ^ (table, &a)).rotate_right_shift_8();
    c = &c + (table, &d);
    b = (&b ^ (table, &c)).rotate_right_shift_7(table);

    *a_ref = a;
    *b_ref = b;
    *c_ref = c;
    *d_ref = d;
}

#[cfg(test)]
mod test {
    use crate::g::g;
    use crate::lookup_table::LookupTableVar;
    use crate::reference::g_reference;
    use crate::u32::U32Var;
    use bitcoin_circle_stark::treepp::*;
    use bitcoin_script_dsl::bvar::{AllocVar, BVar};
    use bitcoin_script_dsl::constraint_system::ConstraintSystem;
    use bitcoin_script_dsl::test_program;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_g() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let mut a = prng.gen();
            let mut b = prng.gen();
            let mut c = prng.gen();
            let mut d = prng.gen();
            let m_0 = prng.gen();
            let m_1 = prng.gen();

            let cs = ConstraintSystem::new_ref();

            let mut a_var = U32Var::new_program_input(&cs, a).unwrap();
            let mut b_var = U32Var::new_program_input(&cs, b).unwrap();
            let mut c_var = U32Var::new_program_input(&cs, c).unwrap();
            let mut d_var = U32Var::new_program_input(&cs, d).unwrap();
            let m_0_var = U32Var::new_program_input(&cs, m_0).unwrap();
            let m_1_var = U32Var::new_program_input(&cs, m_1).unwrap();

            let table = LookupTableVar::new_constant(&cs, ()).unwrap();

            g(
                &table, &mut a_var, &mut b_var, &mut c_var, &mut d_var, &m_0_var, &m_1_var,
            );
            g_reference(&mut a, &mut b, &mut c, &mut d, m_0, m_1);

            let expected_a_var = U32Var::new_constant(&cs, a).unwrap();
            let expected_b_var = U32Var::new_constant(&cs, b).unwrap();
            let expected_c_var = U32Var::new_constant(&cs, c).unwrap();
            let expected_d_var = U32Var::new_constant(&cs, d).unwrap();

            a_var.equalverify(&expected_a_var).unwrap();
            b_var.equalverify(&expected_b_var).unwrap();
            c_var.equalverify(&expected_c_var).unwrap();
            d_var.equalverify(&expected_d_var).unwrap();

            cs.set_program_output(&a_var).unwrap();
            cs.set_program_output(&b_var).unwrap();
            cs.set_program_output(&c_var).unwrap();
            cs.set_program_output(&d_var).unwrap();

            let mut values = vec![];
            for v in [a, b, c, d].iter() {
                let mut v = *v;
                for _ in 0..8 {
                    values.push(v & 15);
                    v >>= 4;
                }
            }

            test_program(
                cs,
                script! {
                    { values }
                },
            )
            .unwrap()
        }
    }
}
