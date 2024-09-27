pub mod derivation;
pub mod mnemonic;
fn main() {
    let mnemonic = mnemonic::Mnemonic::new(mnemonic::MnemonicLen::M12).unwrap();

    println!("this is of seed : {:?}", mnemonic.get_pharse());
    let seed = &mnemonic.to_seed("");
    let key = derivation::ExtendedKey::derive_from_path(*seed, "m/44'/0'/0'/0").unwrap();
    key.serialize_xprv();
    key.serialize_xpub();
}
