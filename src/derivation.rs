use crate::mnemonic::Seed;
use hmac::digest::generic_array::GenericArray;
use hmac::Hmac;
use hmac::Mac;
use secp256k1::ecdsa::Signature;
use sha2::Sha512;
pub type PrivateKey = [u8; 32];
pub type ChainCode = [u8; 32];
use k256::elliptic_curve::PrimeField;
use k256::Scalar;
type HmacSha512 = Hmac<Sha512>;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
type KeyFingerprint = [u8; 4];
const DERIVATION_RANGE: u32 = 1 << 31;
use base58::ToBase58;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

pub struct ExtendedKey {
    private_key: PrivateKey,
    attrs: ExtendedKeyAttrs,
}

pub struct ExtendedKeyAttrs {
    pub depth: u8,

    pub parent_fingerprint: KeyFingerprint,

    pub child_number: u32,

    pub chain_code: ChainCode,
}

impl ExtendedKey {
    pub fn new(seed: Seed) -> ExtendedKey {
        Self::derive_from_path(seed, "m").unwrap()
    }

    fn generate_mastere_key(seed: &Seed) -> (PrivateKey, ChainCode) {
        let hmac_key = b"Bitcoin seed";
        let mut mac = HmacSha512::new_from_slice(hmac_key).expect("HMAC can take key of any size");
        mac.update(seed);
        let result = mac.finalize().into_bytes();
        let root: [u8; 64] = result.to_vec().try_into().unwrap();
        (
            root[0..32].try_into().unwrap(),
            root[32..].try_into().unwrap(),
        )
    }

    pub fn derive_from_path(seed: Seed, path: &str) -> anyhow::Result<ExtendedKey> {
        let result = Self::validate_path(path).unwrap();

        let (root_private_key, root_chain_code) = Self::generate_mastere_key(&seed);
        let mut extended_key = ExtendedKey {
            private_key: root_private_key,
            attrs: ExtendedKeyAttrs {
                depth: 0,
                parent_fingerprint: KeyFingerprint::default(),
                child_number: u32::default(),
                chain_code: root_chain_code,
            },
        };
        for (index, value) in result.iter().enumerate() {
            let fingerprint = Self::calculate_fingerprint(&extended_key.public_key());
            if *value >= DERIVATION_RANGE {
                let (private_key, chain_code) = Self::hardened_derive_key(extended_key, *value);
                extended_key = ExtendedKey {
                    private_key,
                    attrs: ExtendedKeyAttrs {
                        depth: (index + 1).try_into().unwrap(),
                        parent_fingerprint: fingerprint,
                        child_number: *value,
                        chain_code,
                    },
                }
            } else {
                let (private_key, chain_code) = Self::normal_derive_key(extended_key, *value);
                extended_key = ExtendedKey {
                    private_key,
                    attrs: ExtendedKeyAttrs {
                        depth: (index + 1).try_into().unwrap(),
                        parent_fingerprint: fingerprint,
                        child_number: *value,
                        chain_code,
                    },
                }
            }
        }

        Ok(extended_key)
    }

    pub fn public_key(&self) -> PublicKey {
        let secp = Secp256k1::new();
        let private_key = self.private_key.clone().to_vec();
        let secret_key = SecretKey::from_slice(&private_key).expect("32 bytes, within curve order");

        PublicKey::from_secret_key(&secp, &secret_key)
    }

    fn point(p: &[u8; 32]) -> PublicKey {
        let secp = Secp256k1::new();

        let secret_key = SecretKey::from_slice(p).expect("Invalid secret key");

        PublicKey::from_secret_key(&secp, &secret_key)
    }

    fn ser_p(p: PublicKey) -> Vec<u8> {
        p.serialize().to_vec()
    }
    fn normal_derive_key(extended_key: ExtendedKey, index: u32) -> (PrivateKey, ChainCode) {
        let mut data = Self::ser_p(Self::point(&extended_key.private_key));
        let pcc = &extended_key.attrs.chain_code.to_vec();
        let i = index.to_be_bytes().to_vec();
        data.extend_from_slice(&i);

        let mut mac = HmacSha512::new_from_slice(pcc).expect("HMAC can take key of any size");
        mac.update(&data);
        let result = mac.finalize().into_bytes();
        let result: [u8; 64] = *result.as_ref();

        let left: [u8; 32] = result[0..32]
            .try_into()
            .expect("Slice with incorrect length");
        let right: [u8; 32] = result[32..64]
            .try_into()
            .expect("Slice with incorrect length");
        let left_scalar = Scalar::from_repr(GenericArray::clone_from_slice(&left))
            .expect("Failed to convert left part to scalar");

        let parent_scalar =
            Scalar::from_repr(GenericArray::clone_from_slice(&extended_key.private_key))
                .expect("Failed to convert parent private key to scalar");

        let child_scalar = left_scalar + parent_scalar;

        if child_scalar.is_zero().into() {
            panic!("Invalid derived key: 2^127 probability event occurred");
        }

        let child_privkey_bytes = child_scalar.to_bytes();

        (child_privkey_bytes.into(), right)
    }

    fn hardened_derive_key(extended_key: ExtendedKey, index: u32) -> (PrivateKey, ChainCode) {
        let index_bytes = index.to_be_bytes();
        let mut mac = HmacSha512::new_from_slice(&extended_key.attrs.chain_code)
            .expect("HMAC can take key of any size");
        mac.update(&[0]);
        mac.update(&extended_key.private_key);
        mac.update(&index_bytes);
        let result = mac.finalize().into_bytes();
        let result: [u8; 64] = *result.as_ref();

        let left: [u8; 32] = result[0..32]
            .try_into()
            .expect("Slice with incorrect length");
        let right: [u8; 32] = result[32..64]
            .try_into()
            .expect("Slice with incorrect length");

        let left_scalar = Scalar::from_repr(GenericArray::clone_from_slice(&left))
            .expect("Failed to convert left part to scalar");

        let parent_scalar =
            Scalar::from_repr(GenericArray::clone_from_slice(&extended_key.private_key))
                .expect("Failed to convert parent private key to scalar");

        let child_scalar = left_scalar + parent_scalar;

        if child_scalar.is_zero().into() {
            panic!("Invalid derived key: 2^127 probability event occurred");
        }

        let child_privkey_bytes = child_scalar.to_bytes();

        (child_privkey_bytes.into(), right)
    }
    fn validate_path(path: &str) -> anyhow::Result<Vec<u32>> {
        let parts: Vec<&str> = path.split('/').collect();

        if parts.is_empty() || parts[0] != "m" {
            anyhow::bail!("invalida first char")
        }

        let mut result: Vec<u32> = vec![];
        for part in parts.iter().skip(1) {
            if let Some(stripped) = part.strip_suffix('\'') {
                let mut number = stripped.parse::<u32>().unwrap();
                number += DERIVATION_RANGE;
                result.push(number);
            } else {
                let number = part.parse::<u32>().unwrap();
                result.push(number);
            };
        }

        Ok(result)
    }
    fn calculate_fingerprint(public_key: &PublicKey) -> [u8; 4] {
        let serialized_pubkey = public_key.serialize();

        let sha256_hash = Sha256::digest(serialized_pubkey);

        let ripemd160_hash = Ripemd160::digest(sha256_hash);

        ripemd160_hash[0..4].try_into().unwrap()
    }
    pub fn serialize_xprv(&self) {
        let child_private_key = self.private_key.to_vec();
        let cc = self.attrs.chain_code.to_vec();
        let version: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4]; // BIP-32 xprv 版本

        let depth = self.attrs.depth.to_be_bytes();

        let child_index = self.attrs.child_number.to_be_bytes();

        let mut private_key_with_prefix = vec![0x00];
        private_key_with_prefix.extend_from_slice(&child_private_key);

        let mut xprv_data = Vec::new();
        xprv_data.extend_from_slice(&version);
        xprv_data.extend_from_slice(&depth);
        xprv_data.extend_from_slice(&self.attrs.parent_fingerprint);
        xprv_data.extend_from_slice(&child_index);
        xprv_data.extend_from_slice(&cc);
        xprv_data.extend_from_slice(&private_key_with_prefix);

        let mut hasher = Sha256::new();
        hasher.update(&xprv_data);
        let first_hash = hasher.finalize();

        let mut hasher = Sha256::new();
        hasher.update(first_hash);
        let checksum = &hasher.finalize()[0..4];

        xprv_data.extend_from_slice(checksum);

        let xprv_base58 = xprv_data.to_base58();
        println!("Base58Check Encoded xprv: {}", xprv_base58);
    }

    pub fn serialize_xpub(&self) {
        let child_private_key = self.public_key().serialize();
        let cc = self.attrs.chain_code.to_vec();
        let version: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];

        let depth = self.attrs.depth.to_be_bytes();

        let child_index = self.attrs.child_number.to_be_bytes();

        let mut xprv_data = Vec::new();
        xprv_data.extend_from_slice(&version);
        xprv_data.extend_from_slice(&depth);
        xprv_data.extend_from_slice(&self.attrs.parent_fingerprint);
        xprv_data.extend_from_slice(&child_index);
        xprv_data.extend_from_slice(&cc);
        xprv_data.extend_from_slice(&child_private_key);

        let mut hasher = Sha256::new();
        hasher.update(&xprv_data);
        let first_hash = hasher.finalize();

        let mut hasher = Sha256::new();
        hasher.update(first_hash);
        let checksum = &hasher.finalize()[0..4];

        xprv_data.extend_from_slice(checksum);

        let xprv_base58 = xprv_data.to_base58();
        println!("Base58Check Encoded xprv: {}", xprv_base58);
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        let message = Self::new_message(message);
        let secret_key = SecretKey::from_slice(&self.private_key).unwrap();
        let secp = Secp256k1::new();
        secp.sign_ecdsa(&message, &secret_key)
    }

    pub fn verify(&self, message: &[u8], sign: Signature) -> anyhow::Result<()> {
        let secp = Secp256k1::new();
        let message = Self::new_message(message);
        secp.verify_ecdsa(&message, &sign, &self.public_key())
            .unwrap();
        Ok(())
    }

    fn new_message(message: &[u8]) -> Message {
        let mut hasher = Sha256::new();
        hasher.update(message);
        let message_hash = hasher.finalize();
        Message::from_digest_slice(&message_hash).expect("消息哈希必须是 32 字节")
    }
}
