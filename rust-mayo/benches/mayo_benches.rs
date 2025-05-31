use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rust_mayo::crypto::{generate_keypair_generic, sign_generic, verify_generic};
use rust_mayo::params::Mayo1; // Start with Mayo1

fn bench_mayo1_keygen(c: &mut Criterion) {
    c.bench_function("MAYO1 KeyGen", |b| {
        b.iter(|| generate_keypair_generic::<Mayo1>().unwrap())
    });
}

fn bench_mayo1_sign(c: &mut Criterion) {
    let (sk, _pk) = generate_keypair_generic::<Mayo1>().unwrap();
    let message = b"test message for benchmarking";
    c.bench_function("MAYO1 Sign", |b| {
        b.iter(|| sign_generic::<Mayo1>(black_box(&sk), black_box(message)))
    });
}

fn bench_mayo1_verify(c: &mut Criterion) {
    let (sk, pk) = generate_keypair_generic::<Mayo1>().unwrap();
    let message = b"test message for benchmarking";
    let signature = sign_generic::<Mayo1>(&sk, message).unwrap();
    c.bench_function("MAYO1 Verify", |b| {
        b.iter(|| verify_generic::<Mayo1>(black_box(&pk), black_box(message), black_box(&signature)))
    });
}

criterion_group!(benches, bench_mayo1_keygen, bench_mayo1_sign, bench_mayo1_verify);
criterion_main!(benches);
