use anyhow::Result;
use bitcoin_script_dsl::bvar::{AllocVar, AllocationMode, BVar};
use bitcoin_script_dsl::constraint_system::{ConstraintSystemRef, Element};

#[derive(Debug, Clone)]
pub struct LookupTableVar {
    pub xor_table_var: XorTableVar,
    pub row_table: RowTable,
}

impl BVar for LookupTableVar {
    type Value = ();

    fn cs(&self) -> ConstraintSystemRef {
        self.xor_table_var.cs().and(&self.row_table.cs())
    }

    fn variables(&self) -> Vec<usize> {
        self.xor_table_var
            .variables()
            .iter()
            .chain(self.row_table.variables.iter())
            .copied()
            .collect()
    }

    fn length() -> usize {
        256 + 16
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
        let xor_table_var = XorTableVar::new_variable(cs, data, mode)?;
        let row_table = RowTable::new_variable(cs, data, mode)?;

        Ok(Self {
            xor_table_var,
            row_table,
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
        let mut variables = vec![];
        for i in 0..16 {
            for j in 0..16 {
                variables.push(cs.alloc(Element::Num(i ^ j), AllocationMode::Constant)?);
            }
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
        for i in 0..16 {
            variables.push(cs.alloc(Element::Num(240 - (i << 4)), AllocationMode::Constant)?);
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
