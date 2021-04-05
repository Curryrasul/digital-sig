use rand::rngs::OsRng;
use num_bigint::RandBigInt;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use rsa::{PublicKey, RSAPrivateKey, RSAPublicKey, PaddingScheme, Hash};

// 2048 bit key
const BITS: usize = 2048;

fn main() {
    println!("...trinket -> car... Command #1 ...\n");

    // Random number generator from OS
    let mut rng = OsRng;

    // let car_private_key = RSAPrivateKey::new(&mut rng, BITS).expect("failed to generate a key");
    // let car_public_key = RSAPublicKey::from(&car_private_key);
    
    // Generating key pair for trinket
    let trinket_private_key = RSAPrivateKey::new(&mut rng, BITS).expect("failed to generate a key");
    let trinket_public_key = RSAPublicKey::from(&trinket_private_key);
    
    // Generated challenge (from car, for trinket) (100bit number)
    let mut challenge = rng
        .gen_bigint(1000)
        .to_bytes_be().1;

    // Vec<u8> to &mut [u8] 
    let challenge = challenge.as_mut_slice();

    println!("...car ->trinket... Challenge data: {:?}\n", challenge);
     
    // New Sha256 hasher
    let mut hasher = Sha256::new();

    // Hashing the challenge
    hasher.input(challenge);

    // Hashed is SHA256(challenge)
    let hashed = &mut [0u8; 32];
    hasher.result(hashed);

    // Making a sig by private trinket's key
    let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256));
    let mut sig = trinket_private_key
        .sign(padding, hashed)
        .expect("Failed to sig");

    println!("...trinket -> car... Sig: {:?}\n", sig);

    // Verifying the sig by public trinket's key
    let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256)); 
    match trinket_public_key.verify(padding, hashed, sig.as_mut_slice()) {
        Ok(_) => println!("Verified"),
        Err(e) => println!("{}", e),
    };
}
