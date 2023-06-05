use std::io::{self, Write};
use ::rand::Rng;
use ::rand::distributions::Uniform;
use rug::{Integer, rand};
use num_primes::Generator;

fn generate_key() -> (Vec<Integer>, u64, Integer) {
    let mut key: Vec<Integer> = Vec::new();
    let p = Integer::from_str_radix(&Generator::safe_prime(506).to_string(), 10).unwrap();
    let mut q;
    loop {
        q = Integer::from_str_radix(&Generator::safe_prime(512).to_string(), 10).unwrap();
        if p.clone().gcd(&q) == 1 {
            break;
        };
    }
    let delta: u64 = (q.clone().div_rem_round(p).0).to_u64().unwrap();
    let mut rand = rand::RandState::new();
    for _ in 0..512 {
        key.push(q.clone().random_below(&mut rand));
    }
    (key, delta, q)
}

fn sample_error(delta: u64, rng: &mut impl Rng) -> i64 {
    let half_delta: f64 = (delta / 2) as f64;
    let half_delta: i64 = half_delta.round() as i64;
    let lower_bound: i64 = 0 - half_delta;
    let upper_bound: i64 = half_delta;
    let range = Uniform::new(lower_bound, upper_bound);
    
    rng.sample(range)
}

fn encrypt_plaintext(plaintext: Integer, k: &[Integer], q: &Integer, delta: u64) -> (Vec<Integer>, Integer) {
    let mut a: Vec<Integer> = Vec::new();
    let mut rand = rand::RandState::new();
    let mut rng = ::rand::thread_rng();
    for _ in 0..512 {
        a.push(q.clone().random_below(&mut rand));
    }
    let mut e;
    loop {
        e = sample_error(delta, &mut rng);
        if (delta * plaintext.clone() + e) < q.clone().div_rem_floor(Integer::from(2)).0 {
            break;
        }
    }
    let mut dot_product = Integer::from(0);
    for i in 0..512 {
        dot_product += a[i].clone() * k[i].clone();
    }
    let b = dot_product + delta * plaintext + Integer::from(e);
    (a, b)
}

fn decrypt_ciphertext(ciphertext: (Vec<Integer>, Integer), q: Integer, k: &[Integer], delta: u64) -> Integer {
    let (a, b) = ciphertext;
    let mut dot_product = Integer::from(0);
    for i in 0..512 {
        dot_product += a[i].clone() * k[i].clone();
    }
    let x = (b - dot_product) % q;
    x.div_rem_round(Integer::from(delta)).0
}

fn verify_homomorphism(m1: Integer, m2: Integer, key: &[Integer], q: &Integer, delta: u64) {
    let sum = m1.clone() + m2.clone();
    let (a1, b1) = encrypt_plaintext(m1.clone(), key.clone(), &q, delta);
    let (a2, b2) = encrypt_plaintext(m2.clone(), key.clone(), &q, delta);
    assert_eq!(decrypt_ciphertext((a1.clone(), b1.clone()), q.clone(), &key, delta), m1.clone(), "Correctness not verified");
    assert_eq!(decrypt_ciphertext((a2.clone(), b2.clone()), q.clone(), &key, delta), m2.clone(), "Correctness not verified");
    assert_eq!(decrypt_ciphertext((a1.clone(), b1.clone() + (Integer::from(delta) * m2.clone())), q.clone(), &key, delta), sum.clone(), "Not additively homomorphic");
    assert_eq!(decrypt_ciphertext((a2.clone(), b2.clone() + (Integer::from(delta) * m1.clone())), q.clone(), &key, delta), sum.clone(), "Not additively homomorphic");
    println!("\nAdditive homomorphism and correctness verified.");
}

fn main() {
    print!("Enter the plaintext: ");
    let mut input = String::new();
    io::stdout().flush().unwrap();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = input.trim();
    let m = Integer::from_str_radix(&hex::encode(input), 16).unwrap();
    let (key, delta, q) = generate_key();
    let ciphertext = encrypt_plaintext(m, &key, &q, delta);
    let mut encoded_ciphertext: (Vec<String>, String) = (Vec::new(), String::new());
    for element in &ciphertext.0 {
        encoded_ciphertext.0.push(base64::encode(element.clone().to_string()));
    }
    encoded_ciphertext.1 = base64::encode(ciphertext.1.to_string());
    println!("\nEncrypted ciphertext: {encoded_ciphertext:?}");
    let output_plaintext = decrypt_ciphertext(ciphertext, q.clone(), &key, delta);
    let output_plaintext = format!("{:X}", &output_plaintext);
    println!("\nDecrypted plaintext: {}", String::from_utf8(hex::decode(output_plaintext).unwrap()).unwrap());
    println!("\nEnter two strings to verify additive homomorphism: ");
    print!("Enter string 1: ");
    let mut input = String::new();
    io::stdout().flush().unwrap();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = input.trim();
    let m1 = Integer::from_str_radix(&hex::encode(input), 16).unwrap();
    print!("Enter string 2: ");
    let mut input = String::new();
    io::stdout().flush().unwrap();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = input.trim();
    let m2 = Integer::from_str_radix(&hex::encode(input), 16).unwrap();
    verify_homomorphism(m1.clone(), m2.clone(), &key, &q, delta);

}
