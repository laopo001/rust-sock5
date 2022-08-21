fn main() {
    use rcgen::generate_simple_self_signed;
    let subject_alt_names = vec!["hello.world.example".to_string(),
        "localhost".to_string()];
    
    let cert = generate_simple_self_signed(subject_alt_names).unwrap();
    // The certificate is now valid for localhost and the domain "hello.world.example"
   
    std::fs::write("cer", cert.serialize_der().unwrap());

    std::fs::write("key", cert.serialize_private_key_der());
}
