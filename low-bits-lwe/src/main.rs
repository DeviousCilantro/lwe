use std::io::{self, Write};
use ::rand::Rng;
use ::rand::distributions::Uniform;
use rug::Integer;
use ring::rand::{SystemRandom, SecureRandom};
use num_primes::Generator;

fn generate_sk() -> (Vec<Integer>, Vec<(Vec<Integer>, Integer)>, u64, Integer, Integer) {
    let mut sk: Vec<Integer> = Vec::new();
    let mut pk: Vec<(Vec<Integer>, Integer)> = Vec::new();
    let rand = SystemRandom::new();
    let p = Integer::from_str_radix(&Generator::safe_prime(506).to_string(), 10).unwrap();
    let mut q;
    loop {
        q = Integer::from_str_radix(&Generator::safe_prime(512).to_string(), 10).unwrap();
        if p.clone().gcd(&q) == 1 {
            break;
        };
    }
    let delta: u64 = (q.clone().div_rem_round(p.clone()).0).to_u64().unwrap();
    for _ in 0..512 {
        sk.push(random_integer(&rand, q.clone()));
    }
    for _ in 0..8192 {
        pk.push(encrypt_plaintext(&Integer::from(0), &sk, &q, &p, delta));
    }
    (sk, pk, delta, q, p)
}

fn random_integer(rng: &SystemRandom, range: Integer) -> Integer {
    loop {
        let mut bytes = vec![0; ((range.significant_bits() + 7) / 8) as usize];
        rng.fill(&mut bytes).unwrap();
        let num = Integer::from_digits(&bytes, rug::integer::Order::Lsf);
        if num < range {
            return num;
        }
    }
}

fn sample_error(delta: u64, rng: &mut impl Rng) -> i64 {
    let half_delta: f64 = (delta / 2) as f64;
    let half_delta: i64 = half_delta.round() as i64;
    let lower_bound: i64 = 0 - half_delta;
    let upper_bound: i64 = half_delta;
    let range = Uniform::new_inclusive(lower_bound, upper_bound);
    rng.sample(range)
}

fn encrypt_plaintext(plaintext: &Integer, k: &[Integer], q: &Integer, p: &Integer, delta: u64) -> (Vec<Integer>, Integer) {
    let mut a: Vec<Integer> = Vec::new();
    let rand = SystemRandom::new();
    let mut rng = ::rand::thread_rng();
    for _ in 0..512 {
        a.push(random_integer(&rand, q.clone()));
    }
    let mut e;
    loop {
        e = sample_error(delta, &mut rng);
        if (plaintext.clone() + p.clone() * e) < q.clone().div_rem_floor(Integer::from(2)).0 {
            break;
        }
    }
    let mut dot_product = Integer::from(0);
    for i in 0..512 {
        dot_product += a[i].clone() * k[i].clone();
    }
    let b = dot_product + plaintext.clone() + p.clone() * Integer::from(e);
    (a, b)
}

fn construct_enc_sum(pk: &[(Vec<Integer>, Integer)]) -> (Vec<Integer>, Integer) {
    let mut rng = ::rand::thread_rng();
    let range = Uniform::new(0, 8192);
    let mut lower_bound: u32;
    let mut upper_bound: u32;
    loop {
        lower_bound = rng.sample(range);
        upper_bound = rng.sample(range);
        if upper_bound > lower_bound {
            break;
        }
    }
    let mut subset: Vec<(Vec<Integer>, Integer)> = Vec::new();
    let mut enc_sum: (Vec<Integer>, Integer) = (Vec::new(), Integer::from(0));
    for _ in lower_bound..upper_bound {
        let choice = rng.sample(range);
        subset.push(pk[choice as usize].clone());
    }
    for i in 0..512 {
        let mut sum = Integer::from(0);
        for element in &subset {
            sum += element.0[i].clone();
            if i == 0 {
                enc_sum.1 += element.1.clone();
            }
        }
        enc_sum.0.push(sum.clone());
    }
    (enc_sum.0, enc_sum.1)
}

fn decrypt_ciphertext(ciphertext: (Vec<Integer>, Integer), q: &Integer, p: &Integer, k: &[Integer]) -> Integer {
    let (a, b) = ciphertext;
    let mut dot_product = Integer::from(0);
    for i in 0..512 {
        dot_product += a[i].clone() * k[i].clone();
    }
    let x = (b - dot_product + q.clone().div_rem_floor(Integer::from(2)).0) % q.clone() - q.clone().div_rem_floor(Integer::from(2)).0;
    x.pow_mod(&Integer::from(1), p).unwrap()
}

fn verify_homomorphism(m1: &Integer, m2: &Integer, sk: &[Integer], q: &Integer, p: &Integer, delta: u64) {
    let sum = m1.clone() + m2.clone();
    let (a1, b1) = encrypt_plaintext(m1, sk, q, p, delta);
    let (a2, b2) = encrypt_plaintext(m2, sk, q, p, delta);
    let mut a3: Vec<Integer> = Vec::new();
    for i in 0..a1.len() {
        a3.push(a1[i].clone() + a2[i].clone());
    }
    let (a3, b3) = (a3.clone(), b1.clone() + b2.clone());
    assert_eq!(decrypt_ciphertext((a1.clone(), b1.clone()), q, p, sk), *m1, "Correctness not verified");
    assert_eq!(decrypt_ciphertext((a2.clone(), b2.clone()), q, p, sk), *m2, "Correctness not verified");
    assert_eq!(decrypt_ciphertext((a1, b1 + m2), q, p, sk), sum, "Not additively homomorphic");
    assert_eq!(decrypt_ciphertext((a2, b2 + m1), q, p, sk), sum, "Not additively homomorphic");
    assert_eq!(decrypt_ciphertext((a3, b3), q, p, sk), sum, "Not additively homomorphic");
    println!("\nAdditive homomorphism and correctness verified.");
}

fn main() {
    print!("\nEnter the plaintext: ");
    let mut input = String::new();
    io::stdout().flush().unwrap();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = input.trim();
    let m = Integer::from_str_radix(&hex::encode(input), 16).unwrap();
    let (sk, pk, delta, q, p) = generate_sk();
    let mut enc_sum;
    loop {
        enc_sum = construct_enc_sum(&pk);
        if decrypt_ciphertext(enc_sum.clone(), &q, &p, &sk) == 0 {
            break;
        }
    }
    let ciphertext = (enc_sum.0, enc_sum.1 + m);
    let mut encoded_ciphertext: (Vec<String>, String) = (Vec::new(), base64::encode(ciphertext.1.to_string()));
    for element in &ciphertext.0 {
        encoded_ciphertext.0.push(base64::encode(element.to_string()));
    }
    println!("\nEncrypted ciphertext: {encoded_ciphertext:?}" );
    let output_plaintext = decrypt_ciphertext(ciphertext, &q, &p, &sk);
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
    verify_homomorphism(&m1, &m2, &sk, &q, &p, delta);
}
