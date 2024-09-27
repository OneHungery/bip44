use bip39::Language;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::Rng;
use sha2::Sha512;

pub struct Mnemonic {
    pub pharse: Vec<&'static str>,
}
pub type Seed = [u8; 64];
pub enum MnemonicLen {
    M12,
    M15,
    M18,
    M21,
    M24,
}

impl Mnemonic {
    pub fn new(word_len: MnemonicLen) -> anyhow::Result<Mnemonic> {
        let entropy_len = Self::get_entropy_len(word_len)?;
        let entropy = Self::generate_entropy(entropy_len)?;
        let mnemonic_phrase = Self::entropy_to_mnemonic(entropy, entropy_len);

        Ok(Mnemonic {
            pharse: mnemonic_phrase,
        })
    }

    pub fn get_pharse(&self) -> Vec<&'static str> {
        self.pharse.clone()
    }
    fn generate_entropy(len: usize) -> anyhow::Result<Vec<u8>> {
        let byte_len = len / 8;
        let mut rng = rand::thread_rng();
        Ok((0..byte_len).map(|_| rng.gen::<u8>()).collect())
    }

    fn get_entropy_len(len: MnemonicLen) -> anyhow::Result<usize> {
        match len {
            MnemonicLen::M12 => Ok(128),
            MnemonicLen::M15 => Ok(160),
            MnemonicLen::M18 => Ok(192),
            MnemonicLen::M21 => Ok(224),
            MnemonicLen::M24 => Ok(256),
        }
    }
    fn entropy_to_mnemonic(entropy: Vec<u8>, entropy_bits: usize) -> Vec<&'static str> {
        let checksum = Self::calculate_checksum(&entropy, entropy_bits);

        let mut bits = vec![];
        for byte in entropy.iter() {
            bits.push(format!("{:08b}", byte));
        }

        let checksum_bits = entropy_bits / 32;
        let checksum_str = format!("{:0width$b}", checksum, width = checksum_bits);
        bits.push(checksum_str);

        let bit_string: String = bits.concat();

        let word_list: &'static [&'static str; 2048] = Language::English.word_list();

        assert_eq!(
            (entropy_bits + checksum_bits) % 11,
            0,
            "位长度必须是 11 的倍数"
        );

        let mut mnemonic = Vec::new();
        for i in (0..bit_string.len()).step_by(11) {
            let segment = &bit_string[i..i + 11];
            let index = u16::from_str_radix(segment, 2).unwrap();
            mnemonic.push(word_list[index as usize]);
        }

        mnemonic
    }

    fn calculate_checksum(entropy: &[u8], entropy_bits: usize) -> u8 {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(entropy);
        let checksum_bits = entropy_bits / 32;
        hash[0] >> (8 - checksum_bits)
    }

    pub fn to_seed(&self, password: &str) -> Seed {
        let mnemonic_str = self.get_pharse().join(" ");

        println!("{:?}", mnemonic_str);
        let salt = format!("mnemonic{}", password);

        let mut seed = vec![0u8; 64];

        let _ = pbkdf2::<Hmac<Sha512>>(mnemonic_str.as_bytes(), salt.as_bytes(), 2048, &mut seed);

        let seed: Seed = seed.try_into().unwrap();

        seed
    }
}
