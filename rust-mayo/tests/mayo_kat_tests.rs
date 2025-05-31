mod common;

// Specific imports from common
use crate::common::{parse_kat_file, KatVector};

// Import crypto functions and parameter types
use rust_mayo::crypto::generate_keypair_generic;
use rust_mayo::params::{Mayo1, Mayo2, Mayo3, Mayo5}; // Import all needed params

// For hex encoding in debug prints
use hex;

#[test]
fn test_kat_mayo1() {
    println!("\nRunning KAT for Mayo1 Key Generation...");
    let kat_file_path = "../KAT/PQCsignKAT_24_MAYO_1.rsp";
    let vectors = parse_kat_file(kat_file_path)
        .expect(&format!("Failed to parse KAT file: {}", kat_file_path));

    let mut success_count = 0;
    let mut tested_vectors_count = 0;

    for (i, vector) in vectors.iter().enumerate() {
        println!("  Testing vector #{} (count={})", i, vector.count);
        if vector.sk.is_empty() || vector.pk.is_empty() {
            println!("    Skipping vector #{} due to empty sk or pk in KAT file.", i);
            continue;
        }
        tested_vectors_count += 1;

        let sk_seed_from_kat = &vector.sk;

        match generate_keypair_generic::<Mayo1>(Some(sk_seed_from_kat)) {
            Ok((our_csk, our_cpk)) => {
                let mut vector_passed = true;
                if our_csk != *sk_seed_from_kat {
                    eprintln!("    FAIL (vector #{}): CSK mismatch!", i);
                    eprintln!("      Expected SK (seed): {}", hex::encode(sk_seed_from_kat));
                    eprintln!("      Actual CSK:         {}", hex::encode(&our_csk));
                    vector_passed = false;
                }
                // Use assert_eq! for immediate failure on critical checks
                assert_eq!(our_csk, *sk_seed_from_kat, "CSK mismatch for vector #{}", i);

                if our_cpk != vector.pk {
                    eprintln!("    FAIL (vector #{}): CPK mismatch!", i);
                    eprintln!("      Expected PK (len {}): {}", vector.pk.len(), hex::encode(&vector.pk));
                    eprintln!("      Actual CPK  (len {}): {}", our_cpk.len(), hex::encode(&our_cpk));
                    if vector.pk.len() == our_cpk.len() {
                        let pk_seed_len = Mayo1::PK_SEED_BYTES;
                        if vector.pk.get(..pk_seed_len) != our_cpk.get(..pk_seed_len) {
                            eprintln!("      PK_SEED part differs:");
                            if let (Some(exp_seed), Some(act_seed)) = (vector.pk.get(..pk_seed_len), our_cpk.get(..pk_seed_len)) {
                                eprintln!("        Expected: {}", hex::encode(exp_seed));
                                eprintln!("        Actual:   {}", hex::encode(act_seed));
                            }
                        }
                        if vector.pk.get(pk_seed_len..) != our_cpk.get(pk_seed_len..) {
                             eprintln!("      Packed P3 part differs.");
                        }
                    }
                    vector_passed = false;
                }
                assert_eq!(our_cpk, vector.pk, "CPK mismatch for vector #{}", i);

                if vector_passed { // This will only be true if both asserts passed
                    success_count += 1;
                    println!("    PASS (vector #{})", i);
                }
            }
            Err(e) => {
                eprintln!("    FAIL (vector #{}): Key generation failed: {:?}", i, e);
                panic!("Key generation failed for vector #{}: {:?}", i, e);
            }
        }
    }
    if tested_vectors_count > 0 {
        assert_eq!(success_count, tested_vectors_count, "Not all KAT vectors for Mayo1 passed keygen test.");
    } else {
        println!("No eligible test vectors found for Mayo1 keygen (sk/pk were empty).");
    }
    println!("Mayo1 Key Generation Tests: {}/{} passed among eligible vectors.", success_count, tested_vectors_count);
}

#[test]
fn test_kat_mayo2() {
    println!("\nRunning KAT for Mayo2 Key Generation...");
    let kat_file_path = "../KAT/PQCsignKAT_32_MAYO_2.rsp";
    let vectors = parse_kat_file(kat_file_path)
        .expect(&format!("Failed to parse KAT file: {}", kat_file_path));

    let mut success_count = 0;
    let mut tested_vectors_count = 0;

    for (i, vector) in vectors.iter().enumerate() {
        println!("  Testing vector #{} (count={})", i, vector.count);
        if vector.sk.is_empty() || vector.pk.is_empty() {
            println!("    Skipping vector #{} due to empty sk or pk in KAT file.", i);
            continue;
        }
        tested_vectors_count += 1;
        let sk_seed_from_kat = &vector.sk;
        match generate_keypair_generic::<Mayo2>(Some(sk_seed_from_kat)) {
            Ok((our_csk, our_cpk)) => {
                assert_eq!(our_csk, *sk_seed_from_kat, "CSK mismatch for vector #{}", i);
                if our_cpk != vector.pk {
                    eprintln!("    FAIL (vector #{}): CPK mismatch for Mayo2!", i);
                    eprintln!("      Expected PK (len {}): {}", vector.pk.len(), hex::encode(&vector.pk));
                    eprintln!("      Actual CPK  (len {}): {}", our_cpk.len(), hex::encode(&our_cpk));
                }
                assert_eq!(our_cpk, vector.pk, "CPK mismatch for vector #{}", i);
                success_count += 1;
                println!("    PASS (vector #{})", i);
            }
            Err(e) => {
                eprintln!("    FAIL (vector #{}): Key generation failed: {:?}", i, e);
                panic!("Key generation failed for Mayo2 vector #{}: {:?}", i, e);
            }
        }
    }
    if tested_vectors_count > 0 {
        assert_eq!(success_count, tested_vectors_count, "Not all KAT vectors for Mayo2 passed keygen test.");
    } else {
        println!("No eligible test vectors found for Mayo2 keygen (sk/pk were empty).");
    }
    println!("Mayo2 Key Generation Tests: {}/{} passed among eligible vectors.", success_count, tested_vectors_count);
}

#[test]
fn test_kat_mayo3() {
    println!("\nRunning KAT for Mayo3 Key Generation...");
    let kat_file_path = "../KAT/PQCsignKAT_40_MAYO_3.rsp";
    let vectors = parse_kat_file(kat_file_path)
        .expect(&format!("Failed to parse KAT file: {}", kat_file_path));

    let mut success_count = 0;
    let mut tested_vectors_count = 0;

    for (i, vector) in vectors.iter().enumerate() {
        println!("  Testing vector #{} (count={})", i, vector.count);
        if vector.sk.is_empty() || vector.pk.is_empty() {
            println!("    Skipping vector #{} due to empty sk or pk in KAT file.", i);
            continue;
        }
        tested_vectors_count += 1;
        let sk_seed_from_kat = &vector.sk;
        match generate_keypair_generic::<Mayo3>(Some(sk_seed_from_kat)) {
            Ok((our_csk, our_cpk)) => {
                assert_eq!(our_csk, *sk_seed_from_kat, "CSK mismatch for vector #{}", i);
                 if our_cpk != vector.pk {
                    eprintln!("    FAIL (vector #{}): CPK mismatch for Mayo3!", i);
                    eprintln!("      Expected PK (len {}): {}", vector.pk.len(), hex::encode(&vector.pk));
                    eprintln!("      Actual CPK  (len {}): {}", our_cpk.len(), hex::encode(&our_cpk));
                }
                assert_eq!(our_cpk, vector.pk, "CPK mismatch for vector #{}", i);
                success_count += 1;
                println!("    PASS (vector #{})", i);
            }
            Err(e) => {
                eprintln!("    FAIL (vector #{}): Key generation failed: {:?}", i, e);
                panic!("Key generation failed for Mayo3 vector #{}: {:?}", i, e);
            }
        }
    }
    if tested_vectors_count > 0 {
        assert_eq!(success_count, tested_vectors_count, "Not all KAT vectors for Mayo3 passed keygen test.");
    } else {
        println!("No eligible test vectors found for Mayo3 keygen (sk/pk were empty).");
    }
    println!("Mayo3 Key Generation Tests: {}/{} passed among eligible vectors.", success_count, tested_vectors_count);
}

#[test]
fn test_kat_mayo5() {
    println!("\nRunning KAT for Mayo5 Key Generation...");
    let kat_file_path = "../KAT/PQCsignKAT_56_MAYO_5.rsp";
    let vectors = parse_kat_file(kat_file_path)
        .expect(&format!("Failed to parse KAT file: {}", kat_file_path));

    let mut success_count = 0;
    let mut tested_vectors_count = 0;

    for (i, vector) in vectors.iter().enumerate() {
        println!("  Testing vector #{} (count={})", i, vector.count);
        if vector.sk.is_empty() || vector.pk.is_empty() {
            println!("    Skipping vector #{} due to empty sk or pk in KAT file.", i);
            continue;
        }
        tested_vectors_count += 1;
        let sk_seed_from_kat = &vector.sk;
        match generate_keypair_generic::<Mayo5>(Some(sk_seed_from_kat)) {
            Ok((our_csk, our_cpk)) => {
                assert_eq!(our_csk, *sk_seed_from_kat, "CSK mismatch for vector #{}", i);
                if our_cpk != vector.pk {
                    eprintln!("    FAIL (vector #{}): CPK mismatch for Mayo5!", i);
                    eprintln!("      Expected PK (len {}): {}", vector.pk.len(), hex::encode(&vector.pk));
                    eprintln!("      Actual CPK  (len {}): {}", our_cpk.len(), hex::encode(&our_cpk));
                }
                assert_eq!(our_cpk, vector.pk, "CPK mismatch for vector #{}", i);
                success_count += 1;
                println!("    PASS (vector #{})", i);
            }
            Err(e) => {
                eprintln!("    FAIL (vector #{}): Key generation failed: {:?}", i, e);
                panic!("Key generation failed for Mayo5 vector #{}: {:?}", i, e);
            }
        }
    }
    if tested_vectors_count > 0 {
        assert_eq!(success_count, tested_vectors_count, "Not all KAT vectors for Mayo5 passed keygen test.");
    } else {
        println!("No eligible test vectors found for Mayo5 keygen (sk/pk were empty).");
    }
    println!("Mayo5 Key Generation Tests: {}/{} passed among eligible vectors.", success_count, tested_vectors_count);
}
