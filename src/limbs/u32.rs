use crate::blake3::lookup_table::LookupTableVar;
use crate::limbs::u4::{NoCarry, U4Var};
use anyhow::Result;
use bitcoin_script_dsl::bvar::{AllocVar, AllocationMode, BVar};
use bitcoin_script_dsl::constraint_system::ConstraintSystemRef;
use std::ops::{Add, BitXor};

#[derive(Debug, Clone)]
pub struct U32Var {
    pub limbs: [U4Var; 8],
}

impl BVar for U32Var {
    type Value = u32;

    fn cs(&self) -> ConstraintSystemRef {
        let mut cs = self.limbs[0].cs();
        for i in 1..8 {
            cs = cs.and(&self.limbs[i].cs());
        }
        cs
    }

    fn variables(&self) -> Vec<usize> {
        let mut variables = vec![];
        for limb in self.limbs.iter() {
            variables.extend(limb.variables());
        }
        variables
    }

    fn length() -> usize {
        8
    }

    fn value(&self) -> Result<Self::Value> {
        let mut value = 0;
        for limb in self.limbs.iter().rev() {
            value <<= 4;
            value += limb.value()?;
        }
        Ok(value)
    }
}

impl AllocVar for U32Var {
    fn new_variable(
        cs: &ConstraintSystemRef,
        mut data: <Self as BVar>::Value,
        mode: AllocationMode,
    ) -> Result<Self> {
        let mut values = vec![];
        for _ in 0..8 {
            values.push(data & 15);
            data >>= 4;
        }

        let limbs = [
            U4Var::new_variable(&cs, values[0], mode)?,
            U4Var::new_variable(&cs, values[1], mode)?,
            U4Var::new_variable(&cs, values[2], mode)?,
            U4Var::new_variable(&cs, values[3], mode)?,
            U4Var::new_variable(&cs, values[4], mode)?,
            U4Var::new_variable(&cs, values[5], mode)?,
            U4Var::new_variable(&cs, values[6], mode)?,
            U4Var::new_variable(&cs, values[7], mode)?,
        ];

        Ok(Self { limbs })
    }
}

impl Add<(&LookupTableVar, &U32Var)> for &U32Var {
    type Output = U32Var;

    fn add(self, rhs: (&LookupTableVar, &U32Var)) -> Self::Output {
        let table = rhs.0;
        let rhs = rhs.1;

        let mut limbs = vec![];

        let (limb, carry) = &self.limbs[0] + (table, &rhs.limbs[0]);
        limbs.push(limb);

        let (limb, carry) = &self.limbs[1] + (table, &rhs.limbs[1], &carry);
        limbs.push(limb);

        let (limb, carry) = &self.limbs[2] + (table, &rhs.limbs[2], &carry);
        limbs.push(limb);

        let (limb, carry) = &self.limbs[3] + (table, &rhs.limbs[3], &carry);
        limbs.push(limb);

        let (limb, carry) = &self.limbs[4] + (table, &rhs.limbs[4], &carry);
        limbs.push(limb);

        let (limb, carry) = &self.limbs[5] + (table, &rhs.limbs[5], &carry);
        limbs.push(limb);

        let (limb, carry) = &self.limbs[6] + (table, &rhs.limbs[6], &carry);
        limbs.push(limb);

        let limb = &self.limbs[7] + (table, &rhs.limbs[7], &carry, NoCarry::default());
        limbs.push(limb);

        let res_var = U32Var {
            limbs: limbs.try_into().unwrap(),
        };
        res_var
    }
}

impl Add<(&LookupTableVar, &U32Var, &U32Var)> for &U32Var {
    type Output = U32Var;

    fn add(self, rhs: (&LookupTableVar, &U32Var, &U32Var)) -> Self::Output {
        let table = rhs.0;
        let rhs_1 = rhs.1;
        let rhs_2 = rhs.2;

        let mut limbs = vec![];

        let (limb, carry) = &self.limbs[0] + (table, &rhs_1.limbs[0], &rhs_2.limbs[0]);
        limbs.push(limb);

        let (limb, carry) = &self.limbs[1] + (table, &rhs_1.limbs[1], &rhs_2.limbs[1], &carry);
        limbs.push(limb);

        let (limb, carry) = &self.limbs[2] + (table, &rhs_1.limbs[2], &rhs_2.limbs[2], &carry);
        limbs.push(limb);

        let (limb, carry) = &self.limbs[3] + (table, &rhs_1.limbs[3], &rhs_2.limbs[3], &carry);
        limbs.push(limb);

        let (limb, carry) = &self.limbs[4] + (table, &rhs_1.limbs[4], &rhs_2.limbs[4], &carry);
        limbs.push(limb);

        let (limb, carry) = &self.limbs[5] + (table, &rhs_1.limbs[5], &rhs_2.limbs[5], &carry);
        limbs.push(limb);

        let (limb, carry) = &self.limbs[6] + (table, &rhs_1.limbs[6], &rhs_2.limbs[6], &carry);
        limbs.push(limb);

        let limb = &self.limbs[7]
            + (
                table,
                &rhs_1.limbs[7],
                &rhs_2.limbs[7],
                &carry,
                NoCarry::default(),
            );
        limbs.push(limb);

        let res_var = U32Var {
            limbs: limbs.try_into().unwrap(),
        };
        res_var
    }
}

impl BitXor<(&LookupTableVar, &U32Var)> for &U32Var {
    type Output = U32Var;

    fn bitxor(self, rhs: (&LookupTableVar, &U32Var)) -> Self::Output {
        let mut limbs = vec![];
        let table = rhs.0;
        let rhs = rhs.1;

        for (l, r) in self.limbs.iter().zip(rhs.limbs.iter()) {
            limbs.push(l ^ (table, r));
        }

        U32Var {
            limbs: limbs.try_into().unwrap(),
        }
    }
}

impl U32Var {
    pub fn rotate_right_shift_16(self) -> Self {
        let limbs = self.limbs;
        let new_limbs = [
            limbs[4].clone(),
            limbs[5].clone(),
            limbs[6].clone(),
            limbs[7].clone(),
            limbs[0].clone(),
            limbs[1].clone(),
            limbs[2].clone(),
            limbs[3].clone(),
        ];
        Self { limbs: new_limbs }
    }

    pub fn rotate_right_shift_12(self) -> Self {
        let limbs = self.limbs;
        let new_limbs = [
            limbs[3].clone(),
            limbs[4].clone(),
            limbs[5].clone(),
            limbs[6].clone(),
            limbs[7].clone(),
            limbs[0].clone(),
            limbs[1].clone(),
            limbs[2].clone(),
        ];
        Self { limbs: new_limbs }
    }

    pub fn rotate_right_shift_8(self) -> Self {
        let limbs = self.limbs;
        let new_limbs = [
            limbs[2].clone(),
            limbs[3].clone(),
            limbs[4].clone(),
            limbs[5].clone(),
            limbs[6].clone(),
            limbs[7].clone(),
            limbs[0].clone(),
            limbs[1].clone(),
        ];
        Self { limbs: new_limbs }
    }

    pub fn rotate_right_shift_7(self, table: &LookupTableVar) -> Self {
        let mut limbs = vec![];
        for i in 0..8 {
            let first = &self.limbs[(i + 1) % 8].get_shr3(table);
            let second = &self.limbs[(i + 2) % 8].get_shl1(table);
            limbs.push(first.add_no_overflow(second));
        }
        let limbs: [U4Var; 8] = limbs.try_into().unwrap();
        Self { limbs }
    }
}

#[cfg(test)]
mod test {
    use crate::blake3::lookup_table::LookupTableVar;
    use crate::limbs::u32::U32Var;
    use bitcoin_circle_stark::treepp::*;
    use bitcoin_script_dsl::bvar::{AllocVar, BVar};
    use bitcoin_script_dsl::constraint_system::ConstraintSystem;
    use bitcoin_script_dsl::test_program_without_opcat;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_u32_add() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let cs = ConstraintSystem::new_ref();

            let a: u32 = prng.gen();
            let b: u32 = prng.gen();

            let a_var = U32Var::new_program_input(&cs, a).unwrap();
            let b_var = U32Var::new_program_input(&cs, b).unwrap();

            let table_var = LookupTableVar::new_constant(&cs, ()).unwrap();

            let res_var = &a_var + (&table_var, &b_var);
            let expected_var = U32Var::new_constant(&cs, a.wrapping_add(b)).unwrap();

            res_var.equalverify(&expected_var).unwrap();

            cs.set_program_output(&res_var).unwrap();

            let mut values = vec![];
            let mut res = a.wrapping_add(b);
            for _ in 0..8 {
                values.push(res & 15);
                res >>= 4;
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

    #[test]
    fn test_u32_rotate_right_shift_7() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let cs = ConstraintSystem::new_ref();
        let a: u32 = prng.gen();
        let shifted_a = a.rotate_right(7);

        let a_var = U32Var::new_program_input(&cs, a).unwrap();
        let table_var = LookupTableVar::new_constant(&cs, ()).unwrap();

        let shifted_a_var = a_var.rotate_right_shift_7(&table_var);
        let expected_var = U32Var::new_constant(&cs, shifted_a).unwrap();
        shifted_a_var.equalverify(&expected_var).unwrap();

        let mut values = vec![];
        let mut res = shifted_a;
        for _ in 0..8 {
            values.push(res & 15);
            res >>= 4;
        }

        cs.set_program_output(&shifted_a_var).unwrap();

        test_program_without_opcat(
            cs,
            script! {
                { values }
            },
        )
        .unwrap();
    }
}
