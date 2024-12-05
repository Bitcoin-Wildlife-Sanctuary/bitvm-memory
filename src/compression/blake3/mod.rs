use crate::limbs::u32::{U32CompactVar, U32Var};
use crate::limbs::u4::U4Var;
use bitcoin_script_dsl::bvar::AllocVar;
use bitcoin_script_dsl::constraint_system::ConstraintSystemRef;
use lookup_table::LookupTableVar;
use round::round;
use std::cmp::min;
use std::ops::AddAssign;

pub mod g;
pub mod lookup_table;
#[cfg(test)]
pub(crate) mod reference;
pub mod round;

pub const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub struct Blake3ConstantVar {
    pub cs: ConstraintSystemRef,
    pub table: LookupTableVar,
    pub zero_u32: U32Var,
    pub iv: Blake3HashVar,
}

impl Blake3ConstantVar {
    pub fn new(cs: &ConstraintSystemRef) -> Blake3ConstantVar {
        Blake3ConstantVar {
            cs: cs.clone(),
            table: LookupTableVar::new_constant(cs, ()).unwrap(),
            zero_u32: U32Var::new_constant(cs, 0).unwrap(),
            iv: Blake3HashVar {
                hash: [
                    U32Var::new_constant(cs, IV[0]).unwrap(),
                    U32Var::new_constant(cs, IV[1]).unwrap(),
                    U32Var::new_constant(cs, IV[2]).unwrap(),
                    U32Var::new_constant(cs, IV[3]).unwrap(),
                    U32Var::new_constant(cs, IV[4]).unwrap(),
                    U32Var::new_constant(cs, IV[5]).unwrap(),
                    U32Var::new_constant(cs, IV[6]).unwrap(),
                    U32Var::new_constant(cs, IV[7]).unwrap(),
                ],
            },
        }
    }
}

#[derive(Clone)]
pub struct Blake3HashVar {
    pub hash: [U32Var; 8],
}

pub fn hash<T: ToU4LimbVar>(constant: &Blake3ConstantVar, v: T) -> Blake3HashVar {
    let cs = constant.cs.clone();

    let mut u4_limbs = v.to_u4_limbs();
    assert_eq!(
        u4_limbs.len() % 2,
        0,
        "The number of u4 limbs should be even (byte aligned)"
    );

    let mut num_block = 0;
    let mut chaining_values = constant.iv.clone();

    while u4_limbs.len() > 0 {
        if num_block > 16 {
            panic!("Too many blocks passed to this Blake3 implementation.");
        }

        let mut messages_u4 = vec![];
        let l = min(512 / 4, u4_limbs.len());
        for _ in 0..l {
            messages_u4.push(u4_limbs.remove(0));
        }
        for _ in l..512 / 4 {
            messages_u4.push(constant.zero_u32.limbs[0].clone());
        }

        let mut messages_u32 = vec![];
        for i in 0..16 {
            messages_u32.push(U32Var {
                limbs: messages_u4[(i * 8 + 0)..(i * 8 + 8)]
                    .to_vec()
                    .try_into()
                    .unwrap(),
            })
        }
        let mut messages_u32: [U32Var; 16] = messages_u32.try_into().unwrap();

        let mut states_u32 = chaining_values.hash.to_vec();
        states_u32.extend_from_slice(&constant.iv.hash[0..4]);
        states_u32.push(constant.zero_u32.clone());
        states_u32.push(constant.zero_u32.clone());
        states_u32.push(U32Var::new_constant(&cs, (l / 2) as u32).unwrap());

        let mut d = 0;
        if num_block == 0 {
            d ^= 1;
        }
        if u4_limbs.is_empty() {
            d ^= 2;
            d ^= 8;
        }
        states_u32.push(U32Var::new_constant(&cs, d).unwrap());

        let mut states_u32: [U32Var; 16] = states_u32.try_into().unwrap();
        for _ in 0..7 {
            round(&constant.table, &mut states_u32, &mut messages_u32);
        }

        let mut new_chaining_values = vec![];
        for i in 0..8 {
            new_chaining_values.push(&states_u32[i] ^ (&constant.table, &states_u32[i + 8]));
        }

        chaining_values = Blake3HashVar {
            hash: new_chaining_values.try_into().unwrap(),
        };
        num_block += 1;
    }

    chaining_values
}

impl AddAssign<(&Blake3ConstantVar, &Blake3HashVar)> for Blake3HashVar {
    fn add_assign(&mut self, rhs: (&Blake3ConstantVar, &Blake3HashVar)) {
        let constant = rhs.0;
        let rhs = rhs.1;

        let mut limbs = self.hash.to_vec();
        limbs.extend(rhs.hash.to_vec());
        *self = hash(&constant, limbs.as_slice())
    }
}

pub trait ToU4LimbVar {
    fn to_u4_limbs(&self) -> Vec<U4Var>;
}

impl ToU4LimbVar for U4Var {
    fn to_u4_limbs(&self) -> Vec<U4Var> {
        vec![self.clone()]
    }
}

impl ToU4LimbVar for U32Var {
    fn to_u4_limbs(&self) -> Vec<U4Var> {
        self.limbs.to_vec()
    }
}

impl<T: ToU4LimbVar> ToU4LimbVar for &[T] {
    fn to_u4_limbs(&self) -> Vec<U4Var> {
        let mut result = vec![];
        for v in self.iter() {
            result.extend(v.to_u4_limbs());
        }
        result
    }
}

#[derive(Clone)]
pub struct Blake3CompactHashVar {
    pub hash: [U32CompactVar; 8],
}

impl From<&Blake3HashVar> for Blake3CompactHashVar {
    fn from(value: &Blake3HashVar) -> Self {
        Self {
            hash: [
                U32CompactVar::from(&value.hash[0]),
                U32CompactVar::from(&value.hash[1]),
                U32CompactVar::from(&value.hash[2]),
                U32CompactVar::from(&value.hash[3]),
                U32CompactVar::from(&value.hash[4]),
                U32CompactVar::from(&value.hash[5]),
                U32CompactVar::from(&value.hash[6]),
                U32CompactVar::from(&value.hash[7]),
            ],
        }
    }
}

impl From<&Blake3CompactHashVar> for Blake3HashVar {
    fn from(value: &Blake3CompactHashVar) -> Self {
        Self {
            hash: [
                U32Var::from(&value.hash[0]),
                U32Var::from(&value.hash[1]),
                U32Var::from(&value.hash[2]),
                U32Var::from(&value.hash[3]),
                U32Var::from(&value.hash[4]),
                U32Var::from(&value.hash[5]),
                U32Var::from(&value.hash[6]),
                U32Var::from(&value.hash[7]),
            ],
        }
    }
}

#[cfg(test)]
mod test {
    use crate::compression::blake3::reference::blake3_reference;
    use crate::compression::blake3::{hash, Blake3ConstantVar};
    use crate::limbs::u32::U32Var;
    use bitcoin_circle_stark::treepp::*;
    use bitcoin_script_dsl::bvar::{AllocVar, BVar};
    use bitcoin_script_dsl::constraint_system::ConstraintSystem;
    use bitcoin_script_dsl::test_program_without_opcat;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_blake3() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let mut messages = Vec::<u32>::with_capacity(16);
        for _ in 0..16 {
            messages.push(prng.gen());
        }

        let cs = ConstraintSystem::new_ref();

        let mut messages_u32 = vec![];
        for &v in messages.iter() {
            messages_u32.push(U32Var::new_program_input(&cs, v).unwrap());
        }

        let constant = Blake3ConstantVar::new(&cs);
        let computed_hash = hash(&constant, messages_u32.as_slice());

        let mut messages = messages.clone();
        let expected = blake3_reference(&mut messages);

        for i in 0..8 {
            let var = U32Var::new_constant(&cs, expected[i]).unwrap();
            computed_hash.hash[i].equalverify(&var).unwrap();
            cs.set_program_output(&computed_hash.hash[i]).unwrap();
        }

        let mut values = vec![];
        for i in 0..8 {
            let mut v = expected[i];
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
