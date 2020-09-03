use std::cmp::{min, max};
use std::time::{Duration, Instant};

fn carry(a: &mut [i32], base: i32) -> i32 {
    let mut carry = 0;
    for i in a.iter_mut() {
        *i += carry;
        carry = *i / base;
        *i %= base;
    }
    carry
}

fn add_mod(a: &[i32], b: &[i32], base: i32) -> Vec<i32> {
    if a.len() < b.len() {
        return add_mod(b, a, base);
    }
    let mut ret = a.to_vec();
    for (i, &x) in b.iter().enumerate() {
        ret[i] += x;
    }
    let carry = carry(&mut ret, base);
    if carry != 0 { ret.push(carry); }
    ret
}

fn sub_mod_unsafe(a: &[i32], b: &[i32], base: i32) -> Vec<i32> {
    let mut ret = a.to_vec();
    for (i, &y) in b.iter().enumerate() {
        ret[i] -= y;
        if ret[i] < 0 {
            ret[i] += base;
            ret[i + 1] -= 1;
        }
    }
    while let Some(0) = ret.last() {
        ret.pop();
    }
    ret
}

fn mul_mod(a: &[i32], b: &[i32], base: i32) -> Vec<i32> {
    let mut ret = vec![0; a.len() + b.len() - 1];
    for (i, &x) in a.iter().enumerate() {
        for (j, &y) in b.iter().enumerate() {
            ret[i + j] += x * y;
        }
    }
    let mut carry = carry(&mut ret, base);
    while carry > 0 {
        ret.push(carry % base);
        carry /= base;
    }
    ret
}

fn mul_mod_karatsuba(a: &[i32], b: &[i32], base: i32) -> Vec<i32> {
    const NAIVE_THRESHOLD: usize = 70;
    if a.len() < NAIVE_THRESHOLD || b.len() < NAIVE_THRESHOLD {
        return mul_mod(a, b, base);
    }
    let half = min(a.len(), b.len()) >> 1;
    let z0 = mul_mod_karatsuba(&a[..half], &b[..half], base);
    let z1 = mul_mod_karatsuba(
        &add_mod(&a[..half], &a[half..], base),
        &add_mod(&b[..half], &b[half..], base),
        base
    );
    let z2 = mul_mod_karatsuba(&a[half..], &b[half..], base);
    let z1 = sub_mod_unsafe(&z1, &add_mod(&z0, &z2, base), base);
    let len = max(max(z0.len(), z1.len() + half), z2.len() + 2 * half);
    let mut ret = z0;
    ret.resize(len, 0);
    for (i, &x) in z1.iter().enumerate() {
        ret[i + half] += x;
    }
    for (i, &x) in z2.iter().enumerate() {
        ret[i + 2 * half] += x;
    }
    let mut carry = carry(&mut ret, base);
    while carry > 0 {
        ret.push(carry % base);
        carry /= base;
    }
    ret
}


pub fn test_radix() {
    let a: Vec<i32> = (0..256).map(|_| rand::random::<u8>() as i32).collect();
    let b: Vec<i32> = (0..256).map(|_| rand::random::<u8>() as i32).collect();

    let start = Instant::now();
    let mut res = vec![];
    for _ in 1..1000 {
        res = mul_mod(&a, &b, 256);
    }
    println!("{:?}", start.elapsed());
    println!("{:?}", res);


    let start = Instant::now();
    let mut res = vec![];
    for _ in 1..1000 {
        res = mul_mod_karatsuba(&a, &b, 256);
    }
    println!("{:?}", start.elapsed());
    println!("{:?}", res);
}