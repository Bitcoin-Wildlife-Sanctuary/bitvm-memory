use anyhow::{Error, Result};
use bitcoin_circle_stark::treepp::*;
use bitcoin_script_dsl::builtins::hash::HashVar;
use bitcoin_script_dsl::builtins::i32::I32Var;
use bitcoin_script_dsl::builtins::u8::U8Var;
use bitcoin_script_dsl::bvar::{AllocVar, AllocationMode};
use bitcoin_script_dsl::constraint_system::ConstraintSystemRef;
use bitcoin_script_dsl::options::Options;
use bitcoin_script_dsl::stack::Stack;
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Winternitz {
    pub secret_seed: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WinternitzMetadata {
    /// Domain separator.
    pub name: String,
    /// The base that the message would be represented over.
    /// If w = 4, it means that every four bits would have a single hash as the signature.
    pub w: usize,
    /// The number of units.
    /// w * l is the number of bits of the accepted message.
    pub l: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WinternitzSecretKey {
    /// The metadata.
    pub metadata: WinternitzMetadata,
    /// The secret key.
    pub secret_key: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WinternitzPublicKey {
    /// The metadata.
    pub metadata: WinternitzMetadata,
    /// The public key.
    pub public_key: Vec<Vec<u8>>,
    /// The succinct public key.
    pub succinct_public_key: Vec<u8>,
}

impl Winternitz {
    pub fn keygen(prng: &mut (impl Rng + CryptoRng)) -> Self {
        let secret_seed: [u8; 32] = prng.gen();
        Self {
            secret_seed: secret_seed.to_vec(),
        }
    }

    pub fn get_secret_key(&self, name: impl ToString, w: usize, l: usize) -> WinternitzSecretKey {
        assert!(w <= 8);

        let mut sha = sha2::Sha256::new();
        Digest::update(&mut sha, &self.secret_seed);
        Digest::update(&mut sha, format!("{},{},{}", name.to_string(), w, l));
        let seed = sha.finalize().to_vec();

        let checksum_l = (l * ((1 << w) - 1) + 1)
            .next_power_of_two()
            .ilog2()
            .div_ceil(w as u32) as usize;
        let total_l = l + checksum_l;

        let mut prng = ChaCha20Rng::from_seed(seed.try_into().unwrap());
        let mut res = vec![];
        for _ in 0..total_l {
            res.push(prng.gen::<[u8; 32]>().to_vec());
        }

        WinternitzSecretKey {
            metadata: WinternitzMetadata {
                name: name.to_string(),
                w,
                l,
            },
            secret_key: res,
        }
    }

    pub fn get_public_key(&self, name: impl ToString, w: usize, l: usize) -> WinternitzPublicKey {
        self.get_secret_key(name, w, l).to_public_key()
    }
}

pub struct WinternitzSignature {
    /// The metadata.
    pub metadata: WinternitzMetadata,
    /// The signatures of messages.
    pub signature_messages: Vec<Vec<u8>>,
    /// The signatures for checksum.
    pub signature_checksum: Vec<Vec<u8>>,
}

impl WinternitzSecretKey {
    pub fn sign(&self, data: &[bool]) -> WinternitzSignature {
        assert!(data.len() <= self.metadata.l * self.metadata.w);

        let mut data = data.to_vec();
        data.resize(self.metadata.l * self.metadata.w, false);

        let mut checksum = 0u32;

        let mut signature_messages = vec![];
        for (secret_key, slice) in self
            .secret_key
            .iter()
            .take(self.metadata.l)
            .zip(data.chunks_exact(self.metadata.w))
        {
            let mut t = 0;
            for i in 0..self.metadata.w {
                if slice[i] {
                    t |= 1 << i;
                }
            }

            checksum += (1 << self.metadata.w) - 1 - t;

            let mut cur = secret_key.to_vec();
            for _ in 0..t {
                cur = sha2::Sha256::digest(&cur).to_vec();
            }
            signature_messages.push(cur);
        }

        let checksum_l = (self.metadata.l * ((1 << self.metadata.w) - 1) + 1)
            .next_power_of_two()
            .ilog2()
            .div_ceil(self.metadata.w as u32) as usize;

        let mut checksum_bits = vec![];
        while checksum != 0 {
            checksum_bits.push(checksum & 1 == 1);
            checksum >>= 1;
        }
        checksum_bits.resize(checksum_l * self.metadata.w, false);

        let mut signature_checksum = vec![];
        for (secret_key, slice) in self
            .secret_key
            .iter()
            .skip(self.metadata.l)
            .zip(checksum_bits.chunks_exact(self.metadata.w))
        {
            let mut t = 0;
            for i in 0..self.metadata.w {
                if slice[i] {
                    t |= 1 << i;
                }
            }

            let mut cur = secret_key.to_vec();
            for _ in 0..t {
                cur = sha2::Sha256::digest(&cur).to_vec();
            }
            signature_checksum.push(cur);
        }

        WinternitzSignature {
            metadata: self.metadata.clone(),
            signature_messages,
            signature_checksum,
        }
    }

    pub fn to_public_key(&self) -> WinternitzPublicKey {
        let mut res = vec![];
        for key in self.secret_key.iter() {
            let mut cur = key.to_vec();
            for _ in 0..((1 << self.metadata.w) - 1) {
                cur = Sha256::digest(&cur).to_vec();
            }
            res.push(cur);
        }

        assert!(res.len() > 0);
        let mut cur = res[0].clone();
        for key in res.iter().skip(1) {
            let mut sha256 = Sha256::new();
            sha256.update(&cur);
            sha256.update(key);
            cur = sha256.finalize().to_vec();
        }

        WinternitzPublicKey {
            metadata: self.metadata.clone(),
            public_key: res,
            succinct_public_key: cur,
        }
    }
}

impl WinternitzPublicKey {
    pub fn verify(&self, data: &[bool], signature: &WinternitzSignature) -> Result<()> {
        assert_eq!(data.len(), self.metadata.l * self.metadata.w);
        assert_eq!(self.metadata, signature.metadata);
        assert_eq!(signature.signature_messages.len(), self.metadata.l);
        assert_eq!(
            signature.signature_checksum.len(),
            self.succinct_public_key.len() - self.metadata.l
        );

        let mut checksum = 0u32;

        let mut hashes = vec![];

        for (signature, slice) in signature
            .signature_messages
            .iter()
            .zip(data.chunks_exact(self.metadata.w))
        {
            let mut t = 0;
            for i in 0..self.metadata.w {
                if slice[i] {
                    t |= 1 << i;
                }
            }

            let t = (1 << self.metadata.w) - 1 - t;
            checksum += t;

            let mut cur = signature.to_vec();
            for _ in 0..t {
                cur = Sha256::digest(&cur).to_vec();
            }
            hashes.push(cur);
        }

        let checksum_l = (self.metadata.l * ((1 << self.metadata.w) - 1) + 1)
            .next_power_of_two()
            .ilog2()
            .div_ceil(self.metadata.w as u32) as usize;

        let mut checksum_bits = vec![];
        while checksum != 0 {
            checksum_bits.push(checksum & 1 == 1);
            checksum >>= 1;
        }
        checksum_bits.resize(checksum_l * self.metadata.w, false);

        for (signature, slice) in signature
            .signature_checksum
            .iter()
            .zip(checksum_bits.chunks_exact(self.metadata.w))
        {
            let mut t = 0;
            for i in 0..self.metadata.w {
                if slice[i] {
                    t |= 1 << i;
                }
            }

            let t = (1 << self.metadata.w) - 1 - t;

            let mut cur = signature.to_vec();
            for _ in 0..t {
                cur = Sha256::digest(&cur).to_vec();
            }
            hashes.push(cur);
        }

        assert!(hashes.len() > 0);
        let mut cur = hashes[0].clone();
        for key in hashes.iter().skip(1) {
            let mut sha256 = Sha256::new();
            sha256.update(&cur);
            sha256.update(key);
            cur = sha256.finalize().to_vec();
        }

        if cur != *self.succinct_public_key {
            return Err(Error::msg("The signature does not match the public key."));
        }

        Ok(())
    }
}

pub struct WinternitzSignatureVar {
    pub signature_messages: Vec<HashVar>,
    pub signature_checksum: Vec<HashVar>,
}

impl WinternitzSignatureVar {
    pub fn from_signature(
        cs: &ConstraintSystemRef,
        signature: &WinternitzSignature,
        allocation_mode: AllocationMode,
    ) -> Result<Self> {
        let message_l = signature.metadata.l;
        let checksum_l = (signature.metadata.l * ((1 << signature.metadata.w) - 1) + 1)
            .next_power_of_two()
            .ilog2()
            .div_ceil(signature.metadata.w as u32) as usize;
        assert_eq!(signature.signature_messages.len(), message_l);
        assert_eq!(signature.signature_checksum.len(), checksum_l);

        let mut signature_messages = vec![];
        for s in signature.signature_messages.iter() {
            signature_messages.push(HashVar::new_variable(&cs, s.clone(), allocation_mode)?);
        }

        let mut signature_checksum = vec![];
        for s in signature.signature_checksum.iter() {
            signature_checksum.push(HashVar::new_variable(&cs, s.clone(), allocation_mode)?);
        }

        Ok(Self {
            signature_messages,
            signature_checksum,
        })
    }
}

impl WinternitzSignatureVar {
    pub fn verify(&self, bytes: &[U8Var], public_key: &WinternitzPublicKey) -> Result<()> {
        let mut cs = bytes[0].cs.clone();
        for byte in bytes.iter().skip(1) {
            cs = cs.and(&byte.cs);
        }
        for signature in self.signature_messages.iter() {
            cs = cs.and(&signature.cs);
        }
        for signature in self.signature_checksum.iter() {
            cs = cs.and(&signature.cs);
        }

        let mut checksum = I32Var::new_constant(
            &cs,
            (((1 << public_key.metadata.w) - 1) * public_key.metadata.l) as i32,
        )?;
        for byte in bytes.iter() {
            checksum = &checksum - byte;
        }

        assert_eq!(bytes.len(), public_key.metadata.l);

        let checksum_l = (public_key.metadata.l * ((1 << public_key.metadata.w) - 1) + 1)
            .next_power_of_two()
            .ilog2()
            .div_ceil(public_key.metadata.w as u32) as usize;

        assert_eq!(self.signature_messages.len(), public_key.metadata.l);
        assert_eq!(self.signature_checksum.len(), checksum_l);

        for ((byte, signature), public_key_elem) in bytes
            .iter()
            .zip(self.signature_messages.iter())
            .zip(public_key.public_key.iter().take(public_key.metadata.l))
        {
            cs.insert_script_complex(
                apply_and_check_repeated_hash,
                [
                    HashVar::new_constant(&cs, public_key_elem.clone())?.variable,
                    signature.variable,
                    byte.variable,
                ],
                &Options::new().with_u32("w", public_key.metadata.w as u32),
            )?;
        }

        let checksum_bytes = checksum.to_positive_limbs(checksum_l, public_key.metadata.w)?;
        assert_eq!(checksum_bytes.len(), checksum_l);

        for ((byte, signature), public_key_elem) in checksum_bytes
            .iter()
            .zip(self.signature_checksum.iter())
            .zip(public_key.public_key.iter().skip(public_key.metadata.l))
        {
            cs.insert_script_complex(
                apply_and_check_repeated_hash,
                [
                    HashVar::new_constant(&cs, public_key_elem.clone())?.variable,
                    signature.variable,
                    byte.variable,
                ],
                &Options::new().with_u32("w", public_key.metadata.w as u32),
            )?;
        }

        Ok(())
    }
}

fn apply_and_check_repeated_hash(_: &mut Stack, options: &Options) -> Result<Script> {
    let w = options.get_u32("w")? as usize;

    Ok(script! {
        { (1 << w) - 1 } OP_SWAP OP_SUB
        OP_TOALTSTACK

        for i in 0..w {
            OP_FROMALTSTACK

            if i != w - 1 {
                OP_DUP { 1 << (w - 1 - i) } OP_GREATERTHANOREQUAL OP_IF
                    { 1 << (w - 1 - i) } OP_SUB OP_TOALTSTACK
                    for _ in 0..1 << (w - 2 - i) {
                        OP_HASH256
                    }
                OP_ELSE
                    OP_TOALTSTACK
                OP_ENDIF
            } else {
                OP_IF
                    OP_SHA256
                OP_ENDIF
            }
        }

        OP_EQUALVERIFY
    })
}

#[cfg(test)]
mod test {
    use crate::commitment::winternitz::{Winternitz, WinternitzSignatureVar};
    use bitcoin_circle_stark::treepp::*;
    use bitcoin_script_dsl::builtins::u8::U8Var;
    use bitcoin_script_dsl::bvar::{AllocVar, AllocationMode};
    use bitcoin_script_dsl::constraint_system::ConstraintSystem;
    use bitcoin_script_dsl::test_program;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_winternitz() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut test_bits = Vec::<bool>::new();
        for _ in 0..1000 {
            test_bits.push(prng.gen());
        }

        let winternitz = Winternitz::keygen(&mut prng);
        let secret_key = winternitz.get_secret_key("test", 8, 125);
        let public_key = secret_key.to_public_key();

        let signature = secret_key.sign(&test_bits);
        public_key.verify(&test_bits, &signature).unwrap();
    }

    #[test]
    fn test_winternitz_var_ok() {
        const W: usize = 6;

        let l = (1000 + W - 1) / W;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut test_bits = Vec::<bool>::new();
        for _ in 0..1000 {
            test_bits.push(prng.gen());
        }
        test_bits.resize(W * l, false);

        let winternitz = Winternitz::keygen(&mut prng);
        let secret_key = winternitz.get_secret_key("test", W, l);
        let public_key = secret_key.to_public_key();

        let signature = secret_key.sign(&test_bits);

        let cs = ConstraintSystem::new_ref();

        let mut data_var = vec![];
        for chunk in test_bits.chunks(W) {
            let mut constant = 0;
            for i in 0..W {
                if chunk[i] {
                    constant += 1 << i;
                }
            }
            data_var.push(U8Var::new_program_input(&cs, constant).unwrap());
        }

        let signature_var =
            WinternitzSignatureVar::from_signature(&cs, &signature, AllocationMode::ProgramInput)
                .unwrap();
        signature_var.verify(&data_var, &public_key).unwrap();

        test_program(cs, script! {}).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_winternitz_var_err() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut test_bits = Vec::<bool>::new();
        for _ in 0..1000 {
            test_bits.push(prng.gen());
        }

        let winternitz = Winternitz::keygen(&mut prng);
        let secret_key = winternitz.get_secret_key("test", 8, 125);
        let public_key = secret_key.to_public_key();

        let signature = secret_key.sign(&test_bits);

        let cs = ConstraintSystem::new_ref();

        test_bits[0] = !test_bits[0];

        let mut data_var = vec![];
        for chunk in test_bits.chunks(8) {
            let mut constant = 0;
            for i in 0..8 {
                if chunk[i] {
                    constant += 1 << i;
                }
            }
            data_var.push(U8Var::new_program_input(&cs, constant).unwrap());
        }

        let signature_var =
            WinternitzSignatureVar::from_signature(&cs, &signature, AllocationMode::ProgramInput)
                .unwrap();
        signature_var.verify(&data_var, &public_key).unwrap();

        test_program(cs, script! {}).unwrap();
    }
}
