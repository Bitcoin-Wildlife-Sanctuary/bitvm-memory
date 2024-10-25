use crate::lookup_table::LookupTableVar;
use crate::round::round;
use crate::u32::U32Var;
use crate::u4::U4Var;
use bitcoin_script_dsl::bvar::AllocVar;
use bitcoin_script_dsl::constraint_system::ConstraintSystemRef;
use std::ops::AddAssign;

pub const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub struct Blake3ConstantVar {
    pub cs: ConstraintSystemRef,
    pub table: LookupTableVar,
    pub zero_u32: U32Var,
    pub iv: [U32Var; 8],
}

impl Blake3ConstantVar {
    pub fn new(cs: &ConstraintSystemRef) -> Blake3ConstantVar {
        Blake3ConstantVar {
            cs: cs.clone(),
            table: LookupTableVar::new_constant(cs, ()).unwrap(),
            zero_u32: U32Var::new_constant(cs, 0).unwrap(),
            iv: [
                U32Var::new_constant(cs, IV[0]).unwrap(),
                U32Var::new_constant(cs, IV[1]).unwrap(),
                U32Var::new_constant(cs, IV[2]).unwrap(),
                U32Var::new_constant(cs, IV[3]).unwrap(),
                U32Var::new_constant(cs, IV[4]).unwrap(),
                U32Var::new_constant(cs, IV[5]).unwrap(),
                U32Var::new_constant(cs, IV[6]).unwrap(),
                U32Var::new_constant(cs, IV[7]).unwrap(),
            ],
        }
    }
}

pub struct Blake3ChannelVar {
    pub chaining_values: [U32Var; 8],
    pub next_t: u32,
}

impl Blake3ChannelVar {
    pub fn new(constant: &Blake3ConstantVar) -> Blake3ChannelVar {
        Blake3ChannelVar {
            chaining_values: constant.iv.clone(),
            next_t: 0,
        }
    }
}

impl<T: ToU4LimbVar> AddAssign<(&Blake3ConstantVar, &T)> for Blake3ChannelVar {
    fn add_assign(&mut self, rhs: (&Blake3ConstantVar, &T)) {
        let constant = rhs.0;
        let rhs = rhs.1;
        let cs = constant.cs.clone();

        let u4_limbs = rhs.to_u4_limbs();
        assert_eq!(
            u4_limbs.len() % 2,
            0,
            "The number of u4 limbs should be even (byte aligned)"
        );

        let mut iter = u4_limbs.into_iter().peekable();

        let mut flag = false;
        while iter.peek().is_some() {
            let mut messages_u4 = vec![];
            while messages_u4.len() < 512 / 4 && iter.peek().is_some() {
                messages_u4.push(iter.next().unwrap());
            }
            let len = messages_u4.len() / 2;
            while messages_u4.len() < 512 / 4 {
                messages_u4.push(constant.zero_u32.limbs[0].clone());
            }

            let mut messages_u32 = vec![];
            for i in 0..16 {
                messages_u32.push(U32Var {
                    limbs: messages_u4[(i * 4 + 0)..(i * 4 + 8)]
                        .to_vec()
                        .try_into()
                        .unwrap(),
                })
            }
            let mut messages_u32: [U32Var; 16] = messages_u32.try_into().unwrap();

            let mut states_u32 = self.chaining_values.to_vec();
            states_u32.extend_from_slice(&constant.iv[0..4]);
            states_u32.push(constant.zero_u32.clone());
            states_u32.push(U32Var::new_constant(&cs, self.next_t).unwrap());
            states_u32.push(U32Var::new_constant(&cs, len as u32).unwrap());

            let mut d = 0;
            if !flag {
                flag = true;
                d ^= 2 ^ 0;
            }
            if iter.peek().is_none() {
                d ^= 2 ^ 1;
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
            self.chaining_values = new_chaining_values.try_into().unwrap();
        }

        self.next_t += 1;
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
        let mut res = vec![];
        for v in self.iter() {
            res.extend(v.to_u4_limbs());
        }
        res
    }
}

#[cfg(test)]
mod test {
    use crate::blake3::{Blake3ChannelVar, Blake3ConstantVar};
    use crate::u32::U32Var;
    use bitcoin_circle_stark::treepp::*;
    use bitcoin_script_dsl::bvar::AllocVar;
    use bitcoin_script_dsl::constraint_system::ConstraintSystem;
    use bitcoin_script_dsl::test_program;
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
        let mut channel = Blake3ChannelVar::new(&constant);

        channel += (&constant, &messages_u32.as_slice());

        test_program(cs, script! {}).unwrap();
    }
}
