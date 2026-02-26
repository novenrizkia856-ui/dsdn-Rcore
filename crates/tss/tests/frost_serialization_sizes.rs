#[test]
fn frost_serialization_sizes() {
    use frost_ed25519 as frost;
    use rand::rngs::OsRng;
    use std::collections::BTreeMap;

    let (shares, pubkey_package) = frost::keys::generate_with_dealer(
        3, 2, frost::keys::IdentifierList::Default, &mut OsRng
    ).unwrap();

    // VerifyingKey
    let vk_bytes = pubkey_package.verifying_key().serialize().unwrap();
    println!("VerifyingKey serialized len: {}", vk_bytes.len());
    println!("VerifyingKey hex: {:02x?}", &vk_bytes);

    // KeyPackage from first share
    let first_id = *shares.keys().next().unwrap();
    let key_package = frost::keys::KeyPackage::try_from(
        shares.get(&first_id).unwrap().clone()
    ).unwrap();

    // SigningShare - no unwrap, returns Vec<u8> directly
    let ss_bytes = key_package.signing_share().serialize();
    println!("SigningShare serialized len: {}", ss_bytes.len());
    println!("SigningShare hex: {:02x?}", &ss_bytes);

    // Identifier - no unwrap, returns Vec<u8> directly
    let id_bytes = first_id.serialize();
    println!("Identifier serialized len: {}", id_bytes.len());
    println!("Identifier hex: {:02x?}", &id_bytes);

    // SigningCommitments
    let (nonces, commitments) = frost::round1::commit(
        key_package.signing_share(), &mut OsRng
    );
    let sc_bytes = commitments.serialize().unwrap();
    println!("SigningCommitments serialized len: {}", sc_bytes.len());
    println!("SigningCommitments hex: {:02x?}", &sc_bytes);

    // Full signing flow for 2-of-3
    let mut key_packages: BTreeMap<_, _> = BTreeMap::new();
    for (id, share) in &shares {
        key_packages.insert(*id, frost::keys::KeyPackage::try_from(share.clone()).unwrap());
    }

    let mut nonces_map = BTreeMap::new();
    let mut commitments_map = BTreeMap::new();
    let signers: Vec<_> = key_packages.keys().take(2).cloned().collect();
    for id in &signers {
        let kp = &key_packages[id];
        let (n, c) = frost::round1::commit(kp.signing_share(), &mut OsRng);
        nonces_map.insert(*id, n);
        commitments_map.insert(*id, c);
    }

    let message = b"test message";
    let signing_package = frost::SigningPackage::new(commitments_map, message);

    let mut sig_shares = BTreeMap::new();
    for id in &signers {
        let share = frost::round2::sign(
            &signing_package, &nonces_map[id], &key_packages[id]
        ).unwrap();
        sig_shares.insert(*id, share);
    }

    // SignatureShare - no unwrap
    let first_share = sig_shares.values().next().unwrap();
    let share_bytes = first_share.serialize();
    println!("SignatureShare serialized len: {}", share_bytes.len());
    println!("SignatureShare hex: {:02x?}", &share_bytes);

    // Aggregate Signature
    let group_sig = frost::aggregate(&signing_package, &sig_shares, &pubkey_package).unwrap();
    let sig_bytes = group_sig.serialize().unwrap();
    println!("Signature serialized len: {}", sig_bytes.len());
    println!("Signature hex: {:02x?}", &sig_bytes);

    // PublicKeyPackage
    let pkp_bytes = pubkey_package.serialize().unwrap();
    println!("PublicKeyPackage serialized len: {}", pkp_bytes.len());

    // KeyPackage
    let kp_bytes = key_package.serialize().unwrap();
    println!("KeyPackage serialized len: {}", kp_bytes.len());
}