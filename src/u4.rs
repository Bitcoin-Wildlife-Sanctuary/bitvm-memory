use crate::lookup_table::LookupTableVar;
use anyhow::{Error, Result};
use bitcoin_circle_stark::treepp::*;
use bitcoin_script_dsl::bvar::{AllocVar, AllocationMode, BVar};
use bitcoin_script_dsl::constraint_system::{ConstraintSystemRef, Element};
use bitcoin_script_dsl::options::Options;
use bitcoin_script_dsl::stack::Stack;
use std::ops::BitXor;

#[derive(Debug, Clone)]
pub struct U4Var {
    pub variable: usize,
    pub value: u32,
    pub cs: ConstraintSystemRef,
}

impl BVar for U4Var {
    type Value = u32;

    fn cs(&self) -> ConstraintSystemRef {
        self.cs.clone()
    }

    fn variables(&self) -> Vec<usize> {
        vec![self.variable]
    }

    fn length() -> usize {
        1
    }

    fn value(&self) -> Result<Self::Value> {
        if self.value > 15 {
            Err(Error::msg("U4Var has a value that falls beyond u4"))
        } else {
            Ok(self.value)
        }
    }
}

impl BitXor<(&LookupTableVar, &U4Var)> for &U4Var {
    type Output = U4Var;

    fn bitxor(self, rhs: (&LookupTableVar, &U4Var)) -> Self::Output {
        let table = rhs.0;
        let rhs = rhs.1;

        let res = self.value ^ rhs.value;
        let cs = self.cs().and(&table.cs()).and(&rhs.cs());

        let options = Options::new()
            .with_u32("xor_table_ref", table.xor_table_var.variables[0] as u32)
            .with_u32("row_table_ref", table.row_table.variables[0] as u32);
        cs.insert_script_complex(
            u4var_xor,
            self.variables()
                .iter()
                .chain(rhs.variables().iter())
                .copied(),
            &options,
        )
        .unwrap();
        U4Var::new_function_output(&cs, res).unwrap()
    }
}

fn u4var_xor(stack: &mut Stack, options: &Options) -> Result<Script> {
    let last_xor_table_elem = options.get_u32("xor_table_ref")?;
    let k_xor = stack.get_relative_position(last_xor_table_elem as usize)? - 255;

    let last_row_table_elem = options.get_u32("row_table_ref")?;
    let k_row = stack.get_relative_position(last_row_table_elem as usize)? - 15;

    Ok(script! {
        { k_row + 2 } OP_ADD OP_PICK OP_ADD
        { k_xor + 1 } OP_ADD OP_PICK
    })
}

impl AllocVar for U4Var {
    fn new_variable(
        cs: &ConstraintSystemRef,
        data: <Self as BVar>::Value,
        mode: AllocationMode,
    ) -> Result<Self> {
        let variable = cs.alloc(Element::Num(data as i32), mode)?;
        Ok(Self {
            variable,
            value: data,
            cs: cs.clone(),
        })
    }
}

#[cfg(test)]
mod test {
    use crate::lookup_table::LookupTableVar;
    use crate::u4::U4Var;
    use bitcoin_circle_stark::treepp::*;
    use bitcoin_script_dsl::bvar::AllocVar;
    use bitcoin_script_dsl::constraint_system::ConstraintSystem;
    use bitcoin_script_dsl::test_program;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_xor() {
        for _ in 0..100 {
            let cs = ConstraintSystem::new_ref();

            let mut prng = ChaCha20Rng::seed_from_u64(0);
            let a = prng.gen_range(0..16);
            let b = prng.gen_range(0..16);

            let a_var = U4Var::new_program_input(&cs, a).unwrap();
            let b_var = U4Var::new_program_input(&cs, b).unwrap();

            let lookup_table = LookupTableVar::new_constant(&cs, ()).unwrap();

            let res_var = &a_var ^ (&lookup_table, &b_var);
            cs.set_program_output(&res_var).unwrap();

            test_program(
                cs,
                script! {
                    { a ^ b }
                },
            )
            .unwrap();
        }
    }
}
