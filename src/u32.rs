use crate::u4::U4Var;
use anyhow::Result;
use bitcoin_circle_stark::treepp::*;
use bitcoin_script_dsl::bvar::{AllocVar, AllocationMode, BVar};
use bitcoin_script_dsl::constraint_system::ConstraintSystemRef;
use std::ops::Add;

#[derive(Debug, Clone)]
pub struct U32Var {
    limbs: [U4Var; 8],
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

impl Add<&U32Var> for &U32Var {
    type Output = U32Var;

    fn add(self, rhs: &U32Var) -> Self::Output {
        let cs = self.cs().and(&rhs.cs());
        let mut res = self.value().unwrap().wrapping_add(rhs.value().unwrap());

        let mut values = vec![];
        for _ in 0..8 {
            values.push(res & 15);
            res >>= 4;
        }

        let mut variables = vec![];
        for (&left, &right) in self.variables().iter().zip(rhs.variables().iter()).rev() {
            variables.push(left);
            variables.push(right);
        }
        cs.insert_script(u32_u4limbs_add, variables).unwrap();

        let mut limbs = [
            U4Var::new_function_output(&cs, values[7]).unwrap(),
            U4Var::new_function_output(&cs, values[6]).unwrap(),
            U4Var::new_function_output(&cs, values[5]).unwrap(),
            U4Var::new_function_output(&cs, values[4]).unwrap(),
            U4Var::new_function_output(&cs, values[3]).unwrap(),
            U4Var::new_function_output(&cs, values[2]).unwrap(),
            U4Var::new_function_output(&cs, values[1]).unwrap(),
            U4Var::new_function_output(&cs, values[0]).unwrap(),
        ];
        limbs.reverse();

        let res_var = U32Var { limbs };
        res_var
    }
}

fn u32_u4limbs_add() -> Script {
    script! {
        for _ in 0..7 {
            OP_ADD
            OP_DUP 16 OP_GREATERTHANOREQUAL
            OP_IF
                16 OP_SUB
                1
            OP_ELSE
                0
            OP_ENDIF
            OP_SWAP OP_TOALTSTACK
            OP_ADD
        }

        OP_ADD
        OP_DUP 16 OP_GREATERTHANOREQUAL
        OP_IF 16 OP_SUB OP_ENDIF
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
    }
}

#[cfg(test)]
mod test {
    use crate::u32::U32Var;
    use bitcoin_circle_stark::treepp::*;
    use bitcoin_script_dsl::bvar::{AllocVar, BVar};
    use bitcoin_script_dsl::constraint_system::ConstraintSystem;
    use bitcoin_script_dsl::test_program;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_u32_u4limbs_add() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let cs = ConstraintSystem::new_ref();

            let a: u32 = prng.gen();
            let b: u32 = prng.gen();

            let a_var = U32Var::new_program_input(&cs, a).unwrap();
            let b_var = U32Var::new_program_input(&cs, b).unwrap();

            let res_var = &a_var + &b_var;
            let expected_var = U32Var::new_constant(&cs, a.wrapping_add(b)).unwrap();

            res_var.equalverify(&expected_var).unwrap();

            cs.set_program_output(&res_var).unwrap();

            let mut values = vec![];
            let mut res = a.wrapping_add(b);
            for _ in 0..8 {
                values.push(res & 15);
                res >>= 4;
            }

            test_program(
                cs,
                script! {
                    { values }
                },
            )
            .unwrap();
        }
    }
}
