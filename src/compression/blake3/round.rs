use crate::compression::blake3::g::g;
use crate::compression::blake3::lookup_table::LookupTableVar;
use crate::limbs::u32::U32Var;

pub fn round(table: &LookupTableVar, state_ref: &mut [U32Var; 16], msg: &mut [U32Var; 16]) {
    let [ref mut s0, ref mut s1, ref mut s2, ref mut s3, ref mut s4, ref mut s5, ref mut s6, ref mut s7, ref mut s8, ref mut s9, ref mut s10, ref mut s11, ref mut s12, ref mut s13, ref mut s14, ref mut s15] =
        *state_ref;

    g(table, s0, s4, s8, s12, &msg[0], &msg[1]);
    g(table, s1, s5, s9, s13, &msg[2], &msg[3]);
    g(table, s2, s6, s10, s14, &msg[4], &msg[5]);
    g(table, s3, s7, s11, s15, &msg[6], &msg[7]);

    g(table, s0, s5, s10, s15, &msg[8], &msg[9]);
    g(table, s1, s6, s11, s12, &msg[10], &msg[11]);
    g(table, s2, s7, s8, s13, &msg[12], &msg[13]);
    g(table, s3, s4, s9, s14, &msg[14], &msg[15]);

    *msg = [
        msg[2].clone(),
        msg[6].clone(),
        msg[3].clone(),
        msg[10].clone(),
        msg[7].clone(),
        msg[0].clone(),
        msg[4].clone(),
        msg[13].clone(),
        msg[1].clone(),
        msg[11].clone(),
        msg[12].clone(),
        msg[5].clone(),
        msg[9].clone(),
        msg[14].clone(),
        msg[15].clone(),
        msg[8].clone(),
    ];
}

#[cfg(test)]
mod test {
    use crate::compression::blake3::lookup_table::LookupTableVar;
    use crate::compression::blake3::reference::round_reference;
    use crate::compression::blake3::round::round;
    use crate::limbs::u32::U32Var;
    use bitcoin_circle_stark::treepp::*;
    use bitcoin_script_dsl::bvar::{AllocVar, BVar};
    use bitcoin_script_dsl::constraint_system::ConstraintSystem;
    use bitcoin_script_dsl::test_program_without_opcat;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_round() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut state = [0u32; 16];
        for i in 0..16 {
            state[i] = prng.gen();
        }
        let mut msg = [0u32; 16];
        for i in 0..16 {
            msg[i] = prng.gen();
        }

        let cs = ConstraintSystem::new_ref();
        let mut state_var = vec![];
        for v in state.iter() {
            state_var.push(U32Var::new_program_input(&cs, *v).unwrap());
        }
        let mut state_var: [U32Var; 16] = state_var.try_into().unwrap();

        let mut msg_var = vec![];
        for v in msg.iter() {
            msg_var.push(U32Var::new_program_input(&cs, *v).unwrap());
        }
        let mut msg_var: [U32Var; 16] = msg_var.try_into().unwrap();

        let table = LookupTableVar::new_constant(&cs, ()).unwrap();
        round(&table, &mut state_var, &mut msg_var);
        round_reference(&mut state, &mut msg);

        for i in 0..16 {
            state_var[i]
                .equalverify(&U32Var::new_constant(&cs, state[i]).unwrap())
                .unwrap();
            cs.set_program_output(&state_var[i]).unwrap();
        }

        let mut values = vec![];
        for i in 0..16 {
            let mut v = state[i];
            for _ in 0..8 {
                values.push(v & 15);
                v >>= 4;
            }
        }

        test_program_without_opcat(
            cs,
            script! {
                { values }
            },
        )
        .unwrap();
    }
}
