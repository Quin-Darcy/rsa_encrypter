use primer;
use std::fs::File;
use std::io::prelude::*;
use std::io::{Read, BufReader};
use num_bigint::{BigUint, BigInt, RandBigInt, ToBigInt};
use num_traits::{zero, one};


const BITLENGTH: u32 = 256;
const E_BLOCKSIZE: u32 = 64;
const D_BLOCKSIZE: u32 = 16;

fn gcd(a: u32, b: u32) -> u32 {
    if b == 0 {
        return a;
                    
    } else {
        return gcd(b, a%b);
                    
    }    
}

fn lcm(a: u32, b: u32) -> u32 {
    (a / gcd(a, b)) * b        
}

fn bu_gcd(a: BigUint, b: BigUint) -> BigUint {
    if b == BigUint::from(0_u32) {
        return a;            
    } else {
        return bu_gcd(b.clone(), a%b);
                    
    }
}

fn modinv(a0: BigInt, m0: BigInt) -> BigInt {
    if m0 == one() {
        return one();            
    }
    let (mut a, mut m, mut x0, mut inv) = (a0, m0.clone(), zero(), one());
    while a > one() {
        inv -= (&a / &m) * &x0;
        a = &a % &m;
        std::mem::swap(&mut a, &mut m);
        std::mem::swap(&mut x0, &mut inv)                                            
    }
    if inv < zero() { 
        inv += m0;                
    }
    inv            
}

fn encode(file_path: &str, blocksize: u32) -> Result<Vec<BigUint>, std::io::Error> {
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(e) => return Err(e),                    
    };
        
    let mut reader = BufReader::new(file);
    let mut bytes: Vec<u8> = Vec::new();
    let num_bytes: u32 = match reader.read_to_end(&mut bytes) {
        Ok(n) => n as u32,
        Err(e) => return Err(e),                            
    };
    
    let bytes_total: u32 = lcm(num_bytes, blocksize);
    let num_blocks: u32 = bytes_total / blocksize;
    let mut blocks: Vec<BigUint> = Vec::new();
    let mut all_bytes: Vec<u8> = vec![0_u8; bytes_total as usize];

    for i in 0..num_bytes as usize {
        all_bytes[i] = bytes[i];                                    
    }

    for i in 0..num_blocks {
        let lower: usize = (i*blocksize) as usize;
        let upper: usize = ((i+1)*blocksize) as usize;
        blocks.push(BigUint::from_bytes_be(&all_bytes[lower..upper]));
    }
    Ok(blocks)                                
}

fn gen_keys(bit_size: u32) -> ((BigUint, BigUint), (BigUint, BigUint)) {
    let p: BigUint = primer::get_large_prime(bit_size);
    let q: BigUint = primer::get_large_prime(bit_size);
    let mut e: BigUint = BigUint::from(1_u32);
    let factor: BigUint = (&p-1_u32)*(&q-1_u32);
    let mut current_gcd: BigUint = BigUint::from(2_u32);
    while current_gcd != BigUint::from(1_u32) {
        e = rand::thread_rng().gen_biguint(256);
        current_gcd = bu_gcd(e.clone(), factor.clone());                                       
    }
    
    let t: BigInt = BigUint::to_bigint(&e.clone()).unwrap();
    let priv_mod: BigInt = BigUint::to_bigint(&((&p-1_u32)*(&q-1_u32))).unwrap();
    let d: BigUint = modinv(t, priv_mod).to_biguint().unwrap(); 
    ((e.clone(), &p*&q), (d, &p*&q))                            
}

fn map_block(block: &BigUint, key: &(BigUint, BigUint)) -> BigUint {
    block.modpow(&key.0, &key.1)
}

fn crypt(encoded_file: &Vec<BigUint>, key: &(BigUint, BigUint), blocksize: u32) -> Vec<u8> {
    let mut crypt_bytes: Vec<u8> = Vec::new();
    let mut b: Vec<u8>;
    for block in encoded_file {
        b = map_block(&block, key).to_bytes_be();
        let diff: usize = (blocksize-(b.len() as u32)) as usize;
        b.extend(vec![0_u8; diff]);
        crypt_bytes.extend(b);                
    }
    crypt_bytes            
}

fn write_file(encrypted_bytes: &Vec<u8>, path: &str) {
    let mut buffer = match File::create(path) {
        Ok(b) => b,
        Err(_e) => panic!("Error. Could not create file {}", path),                    
    };
    buffer.write_all(&encrypted_bytes[..]).unwrap();    
}

fn main() {
    let keys: ((BigUint, BigUint), (BigUint, BigUint)) = gen_keys(BITLENGTH);
    let fp: &str = "/home/arbegla/Projects/Rust/tests/rsa_enc/src/main.rs";
    let efp: &str = "/home/arbegla/Projects/Rust/tests/rsa_enc/src/enc_main.rs";
    let dfp: &str = "/home/arbegla/Projects/Rust/tests/rsa_enc/src/dec_main.rs";
    
    let encoded_file1: Vec<BigUint> = encode(fp, D_BLOCKSIZE).unwrap();
    let encrypted_bytes: Vec<u8> = crypt(&encoded_file1, &keys.0, E_BLOCKSIZE);
    write_file(&encrypted_bytes, efp);

    let encoded_file2: Vec<BigUint> = encode(efp, E_BLOCKSIZE).unwrap();
    let decrypted_bytes: Vec<u8> = crypt(&encoded_file2, &keys.1, D_BLOCKSIZE);
    write_file(&decrypted_bytes, dfp);    
}
