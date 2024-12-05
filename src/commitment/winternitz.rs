use anyhow::{Error, Result};
use bitcoin_circle_stark::treepp::*;
use bitcoin_script_dsl::builtins::bool::BoolVar;
use bitcoin_script_dsl::constraint_system::ConstraintSystemRef;
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha2::Digest;

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
        assert_eq!(data.len(), self.metadata.l * self.metadata.w);

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
        checksum_bits.resize(checksum_l, false);

        let mut signature_checksum = vec![];
        for (secret_key, slice) in self
            .secret_key
            .iter()
            .skip(self.metadata.l)
            .zip(data.chunks_exact(self.metadata.w))
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
                cur = sha2::Sha256::digest(&cur).to_vec();
            }
            res.push(cur);
        }

        WinternitzPublicKey {
            metadata: self.metadata.clone(),
            public_key: res,
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
            self.public_key.len() - self.metadata.l
        );

        let mut checksum = 0u32;

        for ((public_key, signature), slice) in self
            .public_key
            .iter()
            .take(self.metadata.l)
            .zip(signature.signature_messages.iter())
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
                cur = sha2::Sha256::digest(&cur).to_vec();
            }
            if cur != *public_key {
                return Err(Error::msg("The signature does not match the public key."));
            }
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
        checksum_bits.resize(checksum_l, false);

        for ((public_key, signature), slice) in self
            .public_key
            .iter()
            .skip(self.metadata.l)
            .zip(signature.signature_checksum.iter())
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
                cur = sha2::Sha256::digest(&cur).to_vec();
            }
            if cur != *public_key {
                return Err(Error::msg("The signature does not match the public key."));
            }
        }

        Ok(())
    }
}

pub struct WinternitzGadget;

impl WinternitzGadget {
    pub fn single_hashcheck(cs: &ConstraintSystemRef, w: usize, pubkey: &[u8]) -> Result<BoolVar> {
        todo!()
    }
}

fn hash_from_altstack(pubkey: &[u8]) -> Script {
    todo!()
}

#[cfg(test)]
mod test {
    use crate::commitment::winternitz::Winternitz;
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
}
