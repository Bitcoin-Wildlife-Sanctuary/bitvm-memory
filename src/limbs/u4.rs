use crate::blake3::lookup_table::LookupTableVar;
use anyhow::{Error, Result};
use bitcoin::opcodes::Ordinary::OP_ADD;
use bitcoin_circle_stark::treepp::*;
use bitcoin_script_dsl::bvar::{AllocVar, AllocationMode, BVar};
use bitcoin_script_dsl::constraint_system::{ConstraintSystemRef, Element};
use bitcoin_script_dsl::options::Options;
use bitcoin_script_dsl::stack::Stack;
use std::ops::{Add, BitXor};

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
        { k_row + 1 } OP_ADD OP_PICK OP_ADD
        { k_xor } OP_ADD OP_PICK
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

pub struct CarryVar(U4Var);

#[derive(Default, Copy, Clone)]
pub struct NoCarry();

impl Add<(&LookupTableVar, &U4Var)> for &U4Var {
    type Output = (U4Var, CarryVar);

    fn add(self, rhs: (&LookupTableVar, &U4Var)) -> Self::Output {
        let table = rhs.0;
        let rhs = rhs.1;
        let cs = self.cs().and(&rhs.cs()).and(&table.cs());

        let quotient = (self.value + rhs.value) / 16;
        let remainder = (self.value + rhs.value) % 16;

        cs.insert_script_complex(
            u4_add_and_reduce,
            [self.variable, rhs.variable],
            &Options::new()
                .with_u32(
                    "quotient_table_ref",
                    table.quotient_table_var.variables[0] as u32,
                )
                .with_u32(
                    "remainder_table_ref",
                    table.remainder_table_var.variables[0] as u32,
                )
                .with_u32("num_additions", 1),
        )
        .unwrap();

        let remainder_var = U4Var::new_function_output(&cs, remainder).unwrap();
        let quotient_var = CarryVar(U4Var::new_function_output(&cs, quotient).unwrap());

        (remainder_var, quotient_var)
    }
}

impl Add<(&LookupTableVar, &U4Var, NoCarry)> for &U4Var {
    type Output = U4Var;

    fn add(self, rhs: (&LookupTableVar, &U4Var, NoCarry)) -> Self::Output {
        let table = rhs.0;
        let rhs = rhs.1;
        let cs = self.cs().and(&rhs.cs()).and(&table.cs());
        let remainder = (self.value + rhs.value) % 16;

        cs.insert_script_complex(
            u4_add_and_reduce_nocarry,
            [self.variable, rhs.variable],
            &Options::new()
                .with_u32(
                    "remainder_table_ref",
                    table.remainder_table_var.variables[0] as u32,
                )
                .with_u32("num_additions", 1),
        )
        .unwrap();

        let remainder_var = U4Var::new_function_output(&cs, remainder).unwrap();
        remainder_var
    }
}

impl Add<(&LookupTableVar, &U4Var, &CarryVar)> for &U4Var {
    type Output = (U4Var, CarryVar);

    fn add(self, rhs: (&LookupTableVar, &U4Var, &CarryVar)) -> Self::Output {
        let table = rhs.0;
        let carry = rhs.2;
        let rhs = rhs.1;
        let cs = self.cs().and(&rhs.cs()).and(&table.cs()).and(&carry.0.cs());

        let quotient = (self.value + rhs.value + carry.0.value) / 16;
        let remainder = (self.value + rhs.value + carry.0.value) % 16;

        cs.insert_script_complex(
            u4_add_and_reduce,
            [self.variable, rhs.variable, carry.0.variable],
            &Options::new()
                .with_u32(
                    "quotient_table_ref",
                    table.quotient_table_var.variables[0] as u32,
                )
                .with_u32(
                    "remainder_table_ref",
                    table.remainder_table_var.variables[0] as u32,
                )
                .with_u32("num_additions", 2),
        )
        .unwrap();

        let remainder_var = U4Var::new_function_output(&cs, remainder).unwrap();
        let quotient_var = CarryVar(U4Var::new_function_output(&cs, quotient).unwrap());

        (remainder_var, quotient_var)
    }
}

impl Add<(&LookupTableVar, &U4Var, &CarryVar, NoCarry)> for &U4Var {
    type Output = U4Var;

    fn add(self, rhs: (&LookupTableVar, &U4Var, &CarryVar, NoCarry)) -> Self::Output {
        let table = rhs.0;
        let carry = rhs.2;
        let rhs = rhs.1;
        let cs = self.cs().and(&rhs.cs()).and(&table.cs()).and(&carry.0.cs());

        let remainder = (self.value + rhs.value + carry.0.value) % 16;

        cs.insert_script_complex(
            u4_add_and_reduce_nocarry,
            [self.variable, rhs.variable, carry.0.variable],
            &Options::new()
                .with_u32(
                    "remainder_table_ref",
                    table.remainder_table_var.variables[0] as u32,
                )
                .with_u32("num_additions", 2),
        )
        .unwrap();

        let remainder_var = U4Var::new_function_output(&cs, remainder).unwrap();

        remainder_var
    }
}

impl Add<(&LookupTableVar, &U4Var, &U4Var)> for &U4Var {
    type Output = (U4Var, CarryVar);

    fn add(self, rhs: (&LookupTableVar, &U4Var, &U4Var)) -> Self::Output {
        let table = rhs.0;
        let rhs_1 = rhs.1;
        let rhs_2 = rhs.2;
        let cs = self.cs().and(&rhs_1.cs()).and(&rhs_2.cs()).and(&table.cs());

        let quotient = (self.value + rhs_1.value + rhs_2.value) / 16;
        let remainder = (self.value + rhs_1.value + rhs_2.value) % 16;

        cs.insert_script_complex(
            u4_add_and_reduce,
            [self.variable, rhs_1.variable, rhs_2.variable],
            &Options::new()
                .with_u32(
                    "quotient_table_ref",
                    table.quotient_table_var.variables[0] as u32,
                )
                .with_u32(
                    "remainder_table_ref",
                    table.remainder_table_var.variables[0] as u32,
                )
                .with_u32("num_additions", 2),
        )
        .unwrap();

        let remainder_var = U4Var::new_function_output(&cs, remainder).unwrap();
        let quotient_var = CarryVar(U4Var::new_function_output(&cs, quotient).unwrap());

        (remainder_var, quotient_var)
    }
}

impl Add<(&LookupTableVar, &U4Var, &U4Var, &CarryVar)> for &U4Var {
    type Output = (U4Var, CarryVar);

    fn add(self, rhs: (&LookupTableVar, &U4Var, &U4Var, &CarryVar)) -> Self::Output {
        let table = rhs.0;
        let carry = rhs.3;
        let rhs_1 = rhs.1;
        let rhs_2 = rhs.2;
        let cs = self
            .cs()
            .and(&rhs_1.cs())
            .and(&rhs_2.cs())
            .and(&table.cs())
            .and(&carry.0.cs());

        let quotient = (self.value + rhs_1.value + rhs_2.value + carry.0.value) / 16;
        let remainder = (self.value + rhs_1.value + rhs_2.value + carry.0.value) % 16;

        cs.insert_script_complex(
            u4_add_and_reduce,
            [
                self.variable,
                rhs_1.variable,
                rhs_2.variable,
                carry.0.variable,
            ],
            &Options::new()
                .with_u32(
                    "quotient_table_ref",
                    table.quotient_table_var.variables[0] as u32,
                )
                .with_u32(
                    "remainder_table_ref",
                    table.remainder_table_var.variables[0] as u32,
                )
                .with_u32("num_additions", 3),
        )
        .unwrap();

        let remainder_var = U4Var::new_function_output(&cs, remainder).unwrap();
        let quotient_var = CarryVar(U4Var::new_function_output(&cs, quotient).unwrap());

        (remainder_var, quotient_var)
    }
}

impl Add<(&LookupTableVar, &U4Var, &U4Var, &CarryVar, NoCarry)> for &U4Var {
    type Output = U4Var;

    fn add(self, rhs: (&LookupTableVar, &U4Var, &U4Var, &CarryVar, NoCarry)) -> Self::Output {
        let table = rhs.0;
        let carry = rhs.3;
        let rhs_1 = rhs.1;
        let rhs_2 = rhs.2;
        let cs = self
            .cs()
            .and(&rhs_1.cs())
            .and(&rhs_2.cs())
            .and(&table.cs())
            .and(&carry.0.cs());

        let remainder = (self.value + rhs_1.value + rhs_2.value + carry.0.value) % 16;

        cs.insert_script_complex(
            u4_add_and_reduce_nocarry,
            [
                self.variable,
                rhs_1.variable,
                rhs_2.variable,
                carry.0.variable,
            ],
            &Options::new()
                .with_u32(
                    "remainder_table_ref",
                    table.remainder_table_var.variables[0] as u32,
                )
                .with_u32("num_additions", 3),
        )
        .unwrap();

        let remainder_var = U4Var::new_function_output(&cs, remainder).unwrap();

        remainder_var
    }
}

fn u4_add_and_reduce(stack: &mut Stack, options: &Options) -> Result<Script> {
    let last_quotient_table_elem = options.get_u32("quotient_table_ref")?;
    let k_quotient = stack.get_relative_position(last_quotient_table_elem as usize)? - 47;

    let last_remainder_table_elem = options.get_u32("remainder_table_ref")?;
    let k_remainder = stack.get_relative_position(last_remainder_table_elem as usize)? - 47;

    let num_additions = options.get_u32("num_additions")? as usize;
    Ok(script! {
        for _ in 0..num_additions {
            OP_ADD
        }
        OP_DUP
        { k_remainder + 1 } OP_ADD OP_PICK
        OP_SWAP
        { k_quotient + 1 } OP_ADD OP_PICK
    })
}

fn u4_add_and_reduce_nocarry(stack: &mut Stack, options: &Options) -> Result<Script> {
    let last_remainder_table_elem = options.get_u32("remainder_table_ref")?;
    let k_remainder = stack.get_relative_position(last_remainder_table_elem as usize)? - 47;
    let num_additions = options.get_u32("num_additions")? as usize;
    Ok(script! {
        for _ in 0..num_additions {
            OP_ADD
        }
        { k_remainder } OP_ADD OP_PICK
    })
}

impl U4Var {
    pub fn add_no_overflow(&self, rhs: &Self) -> Self {
        let self_value = self.value;
        let rhs_value = rhs.value;

        let res_value = self_value + rhs_value;
        assert!(res_value < 16);

        let cs = self.cs().and(&rhs.cs());
        cs.insert_script(u4_add_no_overflow, [self.variable, rhs.variable])
            .unwrap();
        U4Var::new_function_output(&cs, res_value).unwrap()
    }

    pub fn get_shl1(&self, table: &LookupTableVar) -> Self {
        let res_value = (self.value << 1) & 15;
        let cs = self.cs().and(&table.cs());
        cs.insert_script_complex(
            u4_get_shl1,
            [self.variable],
            &Options::new().with_u32("shl1_table_ref", table.shl1table_var.variables[0] as u32),
        )
        .unwrap();
        U4Var::new_function_output(&cs, res_value).unwrap()
    }

    pub fn get_shr3(&self, table: &LookupTableVar) -> Self {
        let res_value = self.value >> 3;
        let cs = self.cs().and(&table.cs());
        cs.insert_script_complex(
            u4_get_shr3,
            [self.variable],
            &Options::new().with_u32("shr3_table_ref", table.shr3table_var.variables[0] as u32),
        )
        .unwrap();
        U4Var::new_function_output(&cs, res_value).unwrap()
    }
}

fn u4_add_no_overflow() -> Script {
    Script::from(vec![OP_ADD.to_u8()])
}

fn u4_get_shl1(stack: &mut Stack, options: &Options) -> Result<Script> {
    let last_shl1_table_elem = options.get_u32("shl1_table_ref")?;
    let k_shl1 = stack.get_relative_position(last_shl1_table_elem as usize)? - 15;

    Ok(script! {
        { k_shl1 } OP_ADD OP_PICK
    })
}

fn u4_get_shr3(stack: &mut Stack, options: &Options) -> Result<Script> {
    let last_shr3_table_elem = options.get_u32("shr3_table_ref")?;
    let k_shr3 = stack.get_relative_position(last_shr3_table_elem as usize)? - 15;

    Ok(script! {
        { k_shr3 } OP_ADD OP_PICK
    })
}

#[cfg(test)]
mod test {
    use crate::blake3::lookup_table::LookupTableVar;
    use crate::limbs::u4::U4Var;
    use bitcoin_circle_stark::treepp::*;
    use bitcoin_script_dsl::bvar::AllocVar;
    use bitcoin_script_dsl::constraint_system::ConstraintSystem;
    use bitcoin_script_dsl::test_program_without_opcat;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_xor() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        for _ in 0..100 {
            let cs = ConstraintSystem::new_ref();

            let a = prng.gen_range(0..16);
            let b = prng.gen_range(0..16);

            let a_var = U4Var::new_program_input(&cs, a).unwrap();
            let b_var = U4Var::new_program_input(&cs, b).unwrap();

            let lookup_table = LookupTableVar::new_constant(&cs, ()).unwrap();

            let res_var = &a_var ^ (&lookup_table, &b_var);
            cs.set_program_output(&res_var).unwrap();

            test_program_without_opcat(
                cs,
                script! {
                    { a ^ b }
                },
            )
            .unwrap();
        }
    }
}
