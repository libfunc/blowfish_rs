use blowfish::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    BlowfishLE,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::{random, thread_rng, RngCore};

pub fn libs_compare(c: &mut Criterion) {
    env_logger::builder()
        .format_module_path(false)
        .format_timestamp_nanos()
        .init();

    c.bench_function("blowfish", |b| {
        let id: u64 = random();
        let mut key = [0u8; 56];
        thread_rng().fill_bytes(&mut key);
        let bf = BlowfishLE::new_from_slice(key.as_ref()).unwrap();

        b.iter(|| {
            let mut generic_arr = GenericArray::from(id.to_le_bytes());
            bf.encrypt_block(&mut generic_arr);
            let mut enc = black_box(generic_arr);
            bf.decrypt_block(&mut enc);
            assert_eq!(enc, GenericArray::from(id.to_le_bytes()));
        })
    });

    c.bench_function("blowfish_rs", |b| {
        let id: u64 = random();
        let mut key = [0u8; 56];
        thread_rng().fill_bytes(&mut key);
        let bf = blowfish_rs::Blowfish::new(&key);

        b.iter(|| {
            let enc = black_box(bf.encrypt_u64(id));
            let dec = bf.decrypt_u64(enc);
            assert_eq!(id, dec);
        })
    });
}

criterion_group!(benches, libs_compare);
criterion_main!(benches);
