use anyhow::Result;
use bitcoin_circle_stark::treepp::*;
use bitcoin_script_dsl::bvar::{AllocVar, AllocationMode, BVar};
use bitcoin_script_dsl::constraint_system::{ConstraintSystemRef, Element};

#[derive(Debug, Clone)]
pub struct LookupTableVar {
    pub xor_table_var: XorTableVar,
    pub row_table: RowTable,
    pub shr3table_var: Shr3TableVar,
    pub shl1table_var: Shl1TableVar,
    pub quotient_table_var: QuotientTableVar,
    pub remainder_table_var: RemainderTableVar,
}

impl BVar for LookupTableVar {
    type Value = ();

    fn cs(&self) -> ConstraintSystemRef {
        self.xor_table_var
            .cs()
            .and(&self.row_table.cs())
            .and(&self.shr3table_var.cs())
            .and(&self.shl1table_var.cs())
            .and(&self.quotient_table_var.cs())
            .and(&self.remainder_table_var.cs())
    }

    fn variables(&self) -> Vec<usize> {
        self.xor_table_var
            .variables()
            .iter()
            .chain(self.row_table.variables.iter())
            .chain(self.shr3table_var.variables.iter())
            .chain(self.shl1table_var.variables.iter())
            .chain(self.quotient_table_var.variables.iter())
            .chain(self.remainder_table_var.variables.iter())
            .copied()
            .collect()
    }

    fn length() -> usize {
        XorTableVar::length()
            + RowTable::length()
            + Shr3TableVar::length()
            + Shl1TableVar::length()
            + QuotientTableVar::length()
            + RemainderTableVar::length()
    }

    fn value(&self) -> Result<Self::Value> {
        Ok(())
    }
}

impl AllocVar for LookupTableVar {
    fn new_variable(
        cs: &ConstraintSystemRef,
        data: <Self as BVar>::Value,
        mode: AllocationMode,
    ) -> Result<Self> {
        let shr3table_var = Shr3TableVar::new_variable(cs, data, mode)?;
        let shl1table_var = Shl1TableVar::new_variable(cs, data, mode)?;
        let xor_table_var = XorTableVar::new_variable(cs, data, mode)?;
        let row_table = RowTable::new_variable(cs, data, mode)?;
        let quotient_table_var = QuotientTableVar::new_variable(cs, data, mode)?;
        let remainder_table_var = RemainderTableVar::new_variable(cs, data, mode)?;

        Ok(Self {
            xor_table_var,
            row_table,
            shr3table_var,
            shl1table_var,
            quotient_table_var,
            remainder_table_var,
        })
    }
}

#[derive(Debug, Clone)]
pub struct XorTableVar {
    pub variables: Vec<usize>,
    pub cs: ConstraintSystemRef,
}

impl BVar for XorTableVar {
    type Value = ();

    fn cs(&self) -> ConstraintSystemRef {
        self.cs.clone()
    }

    fn variables(&self) -> Vec<usize> {
        self.variables.clone()
    }

    fn length() -> usize {
        256
    }

    fn value(&self) -> Result<Self::Value> {
        Ok(())
    }
}

impl AllocVar for XorTableVar {
    fn new_variable(
        cs: &ConstraintSystemRef,
        _: <Self as BVar>::Value,
        mode: AllocationMode,
    ) -> Result<Self> {
        assert_eq!(mode, AllocationMode::Constant);
        Self::new_constant(cs, ())
    }

    fn new_constant(cs: &ConstraintSystemRef, _: <Self as BVar>::Value) -> Result<Self> {
        let mut values = vec![];
        for i in (0..16).rev() {
            for j in (0..16).rev() {
                values.push(i ^ j);
            }
        }

        let mut variables = vec![];
        for &v in values.iter() {
            variables.push(cs.alloc(Element::Num(v), AllocationMode::Constant)?);
        }

        Ok(Self {
            variables,
            cs: cs.clone(),
        })
    }

    fn new_program_input(_: &ConstraintSystemRef, _: <Self as BVar>::Value) -> Result<Self> {
        unimplemented!()
    }

    fn new_function_output(_: &ConstraintSystemRef, _: <Self as BVar>::Value) -> Result<Self> {
        unimplemented!()
    }

    fn new_hint(_: &ConstraintSystemRef, _: <Self as BVar>::Value) -> Result<Self> {
        unimplemented!()
    }
}

#[derive(Clone, Debug)]
pub struct RowTable {
    pub variables: Vec<usize>,
    pub cs: ConstraintSystemRef,
}

impl BVar for RowTable {
    type Value = ();

    fn cs(&self) -> ConstraintSystemRef {
        self.cs.clone()
    }

    fn variables(&self) -> Vec<usize> {
        self.variables.clone()
    }

    fn length() -> usize {
        16
    }

    fn value(&self) -> Result<Self::Value> {
        Ok(())
    }
}

impl AllocVar for RowTable {
    fn new_variable(
        cs: &ConstraintSystemRef,
        _: <Self as BVar>::Value,
        mode: AllocationMode,
    ) -> Result<Self> {
        assert_eq!(mode, AllocationMode::Constant);
        Self::new_constant(cs, ())
    }

    fn new_constant(cs: &ConstraintSystemRef, _: <Self as BVar>::Value) -> Result<Self> {
        let mut variables = vec![];
        for i in (0..16).rev() {
            variables.push(cs.alloc(Element::Num(i << 4), AllocationMode::Constant)?);
        }

        Ok(Self {
            variables,
            cs: cs.clone(),
        })
    }

    fn new_program_input(_: &ConstraintSystemRef, _: <Self as BVar>::Value) -> Result<Self> {
        unimplemented!()
    }

    fn new_function_output(_: &ConstraintSystemRef, _: <Self as BVar>::Value) -> Result<Self> {
        unimplemented!()
    }

    fn new_hint(_: &ConstraintSystemRef, _: <Self as BVar>::Value) -> Result<Self> {
        unimplemented!()
    }
}

#[derive(Clone, Debug)]
pub struct Shr3TableVar {
    pub variables: Vec<usize>,
    pub cs: ConstraintSystemRef,
}

impl BVar for Shr3TableVar {
    type Value = ();

    fn cs(&self) -> ConstraintSystemRef {
        self.cs.clone()
    }

    fn variables(&self) -> Vec<usize> {
        self.variables.clone()
    }

    fn length() -> usize {
        16
    }

    fn value(&self) -> Result<Self::Value> {
        Ok(())
    }
}

impl AllocVar for Shr3TableVar {
    fn new_variable(
        cs: &ConstraintSystemRef,
        _: <Self as BVar>::Value,
        mode: AllocationMode,
    ) -> Result<Self> {
        assert_eq!(mode, AllocationMode::Constant);
        Self::new_constant(cs, ())
    }

    fn new_constant(cs: &ConstraintSystemRef, _: <Self as BVar>::Value) -> Result<Self> {
        let mut variables = vec![];
        for i in (0..16).rev() {
            variables.push(cs.alloc(
                Element::Num(((i as u32) >> 3) as i32),
                AllocationMode::Constant,
            )?);
        }

        Ok(Self {
            variables,
            cs: cs.clone(),
        })
    }

    fn new_program_input(_: &ConstraintSystemRef, _: <Self as BVar>::Value) -> Result<Self> {
        unimplemented!()
    }

    fn new_function_output(_: &ConstraintSystemRef, _: <Self as BVar>::Value) -> Result<Self> {
        unimplemented!()
    }

    fn new_hint(_: &ConstraintSystemRef, _: <Self as BVar>::Value) -> Result<Self> {
        unimplemented!()
    }
}

#[derive(Clone, Debug)]
pub struct Shl1TableVar {
    pub variables: Vec<usize>,
    pub cs: ConstraintSystemRef,
}

impl BVar for Shl1TableVar {
    type Value = ();

    fn cs(&self) -> ConstraintSystemRef {
        self.cs.clone()
    }

    fn variables(&self) -> Vec<usize> {
        self.variables.clone()
    }

    fn length() -> usize {
        16
    }

    fn value(&self) -> Result<Self::Value> {
        Ok(())
    }
}

impl AllocVar for Shl1TableVar {
    fn new_variable(
        cs: &ConstraintSystemRef,
        _: <Self as BVar>::Value,
        mode: AllocationMode,
    ) -> Result<Self> {
        assert_eq!(mode, AllocationMode::Constant);
        Self::new_constant(cs, ())
    }

    fn new_constant(cs: &ConstraintSystemRef, _: <Self as BVar>::Value) -> Result<Self> {
        let mut variables = vec![];
        for i in (0..16).rev() {
            variables.push(cs.alloc(
                Element::Num(((i as u32) << 1) as i32 & 15),
                AllocationMode::Constant,
            )?);
        }

        Ok(Self {
            variables,
            cs: cs.clone(),
        })
    }

    fn new_program_input(_: &ConstraintSystemRef, _: <Self as BVar>::Value) -> Result<Self> {
        unimplemented!()
    }

    fn new_function_output(_: &ConstraintSystemRef, _: <Self as BVar>::Value) -> Result<Self> {
        unimplemented!()
    }

    fn new_hint(_: &ConstraintSystemRef, _: <Self as BVar>::Value) -> Result<Self> {
        unimplemented!()
    }
}

#[derive(Clone, Debug)]
pub struct QuotientTableVar {
    pub variables: Vec<usize>,
    pub cs: ConstraintSystemRef,
}

impl BVar for QuotientTableVar {
    type Value = ();

    fn cs(&self) -> ConstraintSystemRef {
        self.cs.clone()
    }

    fn variables(&self) -> Vec<usize> {
        self.variables.clone()
    }

    fn length() -> usize {
        48
    }

    fn value(&self) -> Result<Self::Value> {
        Ok(())
    }
}

impl AllocVar for QuotientTableVar {
    fn new_variable(
        cs: &ConstraintSystemRef,
        _: <Self as BVar>::Value,
        mode: AllocationMode,
    ) -> Result<Self> {
        assert_eq!(mode, AllocationMode::Constant);
        Self::new_constant(cs, ())
    }

    fn new_constant(cs: &ConstraintSystemRef, _: <Self as BVar>::Value) -> Result<Self> {
        let mut variables = vec![];
        cs.insert_script(create_quotient_table, [])?;
        for i in (0..48).rev() {
            variables.push(cs.alloc(Element::Num(i / 16), AllocationMode::FunctionOutput)?);
        }

        Ok(Self {
            variables,
            cs: cs.clone(),
        })
    }

    fn new_program_input(_: &ConstraintSystemRef, _: <Self as BVar>::Value) -> Result<Self> {
        unimplemented!()
    }

    fn new_function_output(_: &ConstraintSystemRef, _: <Self as BVar>::Value) -> Result<Self> {
        unimplemented!()
    }

    fn new_hint(_: &ConstraintSystemRef, _: <Self as BVar>::Value) -> Result<Self> {
        unimplemented!()
    }
}

fn create_quotient_table() -> Script {
    script! {
        // 47 - 32 == 2, 16 numbers
        // 31 - 16 == 1, 16 numbers
        // 15 - 0 == 0, 16 numbers

        OP_PUSHNUM_2
        OP_DUP
        OP_2DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP

        OP_PUSHNUM_1
        OP_DUP
        OP_2DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP

        OP_PUSHBYTES_0
        OP_DUP
        OP_2DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
    }
}

#[derive(Clone, Debug)]
pub struct RemainderTableVar {
    pub variables: Vec<usize>,
    pub cs: ConstraintSystemRef,
}

impl BVar for RemainderTableVar {
    type Value = ();

    fn cs(&self) -> ConstraintSystemRef {
        self.cs.clone()
    }

    fn variables(&self) -> Vec<usize> {
        self.variables.clone()
    }

    fn length() -> usize {
        48
    }

    fn value(&self) -> Result<Self::Value> {
        Ok(())
    }
}

impl AllocVar for RemainderTableVar {
    fn new_variable(
        cs: &ConstraintSystemRef,
        _: <Self as BVar>::Value,
        mode: AllocationMode,
    ) -> Result<Self> {
        assert_eq!(mode, AllocationMode::Constant);
        Self::new_constant(cs, ())
    }

    fn new_constant(cs: &ConstraintSystemRef, _: <Self as BVar>::Value) -> Result<Self> {
        let mut variables = vec![];
        for i in (0..48).rev() {
            variables.push(cs.alloc(Element::Num(i % 16), AllocationMode::Constant)?);
        }

        Ok(Self {
            variables,
            cs: cs.clone(),
        })
    }

    fn new_program_input(_: &ConstraintSystemRef, _: <Self as BVar>::Value) -> Result<Self> {
        unimplemented!()
    }

    fn new_function_output(_: &ConstraintSystemRef, _: <Self as BVar>::Value) -> Result<Self> {
        unimplemented!()
    }

    fn new_hint(_: &ConstraintSystemRef, _: <Self as BVar>::Value) -> Result<Self> {
        unimplemented!()
    }
}

#[cfg(test)]
mod test {
    use crate::lookup_table::LookupTableVar;
    use bitcoin_circle_stark::treepp::*;
    use bitcoin_script_dsl::bvar::AllocVar;
    use bitcoin_script_dsl::constraint_system::ConstraintSystem;
    use bitcoin_script_dsl::test_program_without_opcat;

    #[test]
    fn test_table() {
        let cs = ConstraintSystem::new_ref();
        let _ = LookupTableVar::new_constant(&cs, ()).unwrap();
        test_program_without_opcat(cs, script! {}).unwrap();
    }
}
