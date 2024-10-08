use anyhow::{anyhow, Error};
use ark_bls12_381::{Bls12_381, Fr as Bls12_381_Fr};
use ark_bn254::{Bn254, Fr as Bn254_Fr};
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ethabi::{decode, encode, ethereum_types::U256, ParamType, Token};
use num_bigint::BigInt;
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use std::io::{BufReader, Cursor};
use std::{collections::HashMap, fs::File};
use wasmer::{Module, Store};

use crate::{
    circom::{R1CSFile, R1CS},
    zkey_bls12_381::read_zkey as read_bls12_381_zkey,
    zkey_bn254::read_zkey as read_bn254_zkey,
    CircomBuilder, CircomConfig, CircomReduction, WitnessCalculator,
};

type Result<T> = core::result::Result<T, Error>;

pub struct Input {
    pub maps: HashMap<String, Vec<BigInt>>,
}

pub fn generate_bn254_params(
    wasm: &str,
    r1cs: &str,
    zkey: &str,
    convert: Option<&str>,
) -> Result<()> {
    if let Some(path) = convert {
        let mut zkey_file = File::open(zkey)?;
        let (prover_key, _) = read_bn254_zkey::<File>(&mut zkey_file)?;
        let mut pk_bytes = vec![];
        prover_key
            .serialize_compressed(&mut pk_bytes)
            .map_err(|_| anyhow!("Infallible point"))?;
        std::fs::write(path, pk_bytes)?;
    } else {
        let config = CircomConfig::<Bn254_Fr>::new(wasm, r1cs)
            .map_err(|_| anyhow!("Failed to new circom config"))?;

        let builder = CircomBuilder::new(config);
        let circom = builder.setup();
        let mut rng = ChaChaRng::from_entropy();
        let params = Groth16::<Bn254, CircomReduction>::generate_random_parameters_with_reduction(
            circom, &mut rng,
        )?;

        let mut pk_bytes = vec![];
        params
            .serialize_compressed(&mut pk_bytes)
            .map_err(|_| anyhow!("Infallible point"))?;
        std::fs::write(zkey, pk_bytes)?;
    }

    Ok(())
}

pub fn generate_bls12_381_params(
    wasm: &str,
    r1cs: &str,
    zkey: &str,
    convert: Option<&str>,
) -> Result<()> {
    if let Some(path) = convert {
        let mut zkey_file = File::open(zkey)?;
        let (prover_key, _) = read_bls12_381_zkey::<File>(&mut zkey_file)?;
        let mut pk_bytes = vec![];
        prover_key
            .serialize_compressed(&mut pk_bytes)
            .map_err(|_| anyhow!("Infallible point"))?;
        std::fs::write(path, pk_bytes)?;
    } else {
        let config = CircomConfig::<Bls12_381_Fr>::new(wasm, r1cs)
            .map_err(|_| anyhow!("Failed to new circom config"))?;

        let builder = CircomBuilder::new(config);
        let circom = builder.setup();
        let mut rng = ChaChaRng::from_entropy();
        let params =
            Groth16::<Bls12_381, CircomReduction>::generate_random_parameters_with_reduction(
                circom, &mut rng,
            )?;

        let mut pk_bytes = vec![];
        params
            .serialize_compressed(&mut pk_bytes)
            .map_err(|_| anyhow!("Infallible point"))?;
        std::fs::write(zkey, pk_bytes)?;
    }

    Ok(())
}

pub fn init_bn254_from_bytes(
    wasm: &[u8],
    r1cs: &[u8],
    zkey: &[u8],
    only_pk: bool,
) -> Result<(ProvingKey<Bn254>, CircomConfig<Bn254_Fr>)> {
    let prover_key = init_bn254_params_from_bytes(zkey, only_pk)?;
    let cfg = init_bn254_circom_from_bytes(wasm, r1cs)?;
    Ok((prover_key, cfg))
}

pub fn init_bls12_381_from_bytes(
    wasm: &[u8],
    r1cs: &[u8],
    zkey: &[u8],
    only_pk: bool,
) -> Result<(ProvingKey<Bls12_381>, CircomConfig<Bls12_381_Fr>)> {
    let prover_key = init_bls12_381_params_from_bytes(zkey, only_pk)?;
    let cfg = init_bls12_381_circom_from_bytes(wasm, r1cs)?;
    Ok((prover_key, cfg))
}

pub fn init_bn254_circom_from_bytes(wasm: &[u8], r1cs: &[u8]) -> Result<CircomConfig<Bn254_Fr>> {
    let mut store = Store::default();
    let module = Module::new(&store, wasm)?;
    let wtns = WitnessCalculator::from_module(&mut store, module)
        .map_err(|_| anyhow!("Failed to calculate circom witness"))?;

    let reader = BufReader::new(Cursor::new(r1cs));
    let r1cs_file = R1CSFile::new(reader)?;

    let cfg = CircomConfig {
        store,
        wtns,
        r1cs: R1CS::from(r1cs_file),
        sanity_check: false,
    };

    Ok(cfg)
}

pub fn init_bls12_381_circom_from_bytes(
    wasm: &[u8],
    r1cs: &[u8],
) -> Result<CircomConfig<Bls12_381_Fr>> {
    let mut store = Store::default();
    let module = Module::new(&store, wasm)?;
    let wtns = WitnessCalculator::from_module(&mut store, module)
        .map_err(|_| anyhow!("Failed to calculate circom witness"))?;

    let reader = BufReader::new(Cursor::new(r1cs));
    let r1cs_file = R1CSFile::new(reader)?;

    let cfg = CircomConfig {
        store,
        wtns,
        r1cs: R1CS::from(r1cs_file),
        sanity_check: false,
    };

    Ok(cfg)
}

pub fn init_bn254_params_from_bytes(zkey: &[u8], only_pk: bool) -> Result<ProvingKey<Bn254>> {
    let mut zkey_reader = BufReader::new(Cursor::new(zkey));
    let prover_key = if only_pk {
        ProvingKey::deserialize_compressed(zkey_reader)?
    } else {
        let (prover_key, _) = read_bn254_zkey(&mut zkey_reader)?;
        prover_key
    };

    Ok(prover_key)
}

pub fn init_bls12_381_params_from_bytes(
    zkey: &[u8],
    only_pk: bool,
) -> Result<ProvingKey<Bls12_381>> {
    let mut zkey_reader = BufReader::new(Cursor::new(zkey));
    let prover_key = if only_pk {
        ProvingKey::deserialize_compressed(zkey_reader)?
    } else {
        let (prover_key, _) = read_bls12_381_zkey(&mut zkey_reader)?;
        prover_key
    };

    Ok(prover_key)
}

pub fn prove_bn254(
    params: &ProvingKey<Bn254>,
    config: CircomConfig<Bn254_Fr>,
    input: Input,
) -> Result<(Vec<Bn254_Fr>, Proof<Bn254>)> {
    prove::<Bn254>(params, config, input)
}

pub fn prove_bls12_381(
    params: &ProvingKey<Bls12_381>,
    config: CircomConfig<Bls12_381_Fr>,
    input: Input,
) -> Result<(Vec<Bls12_381_Fr>, Proof<Bls12_381>)> {
    prove::<Bls12_381>(params, config, input)
}

pub fn verify_bn254(
    params: &VerifyingKey<Bn254>,
    publics: &[Bn254_Fr],
    proof: &Proof<Bn254>,
) -> Result<bool> {
    verify::<Bn254>(params, publics, proof)
}

pub fn verify_bls12_381(
    params: &VerifyingKey<Bls12_381>,
    publics: &[Bls12_381_Fr],
    proof: &Proof<Bls12_381>,
) -> Result<bool> {
    verify::<Bls12_381>(params, publics, proof)
}

pub fn prove<E: Pairing>(
    params: &ProvingKey<E>,
    config: CircomConfig<E::ScalarField>,
    input: Input,
) -> Result<(Vec<E::ScalarField>, Proof<E>)> {
    let mut builder = CircomBuilder::new(config);
    builder.push_inputs(input.maps);

    let circom = builder.build().map_err(|_| anyhow!("Failed to build"))?;
    let pi = circom
        .get_public_inputs()
        .ok_or_else(|| anyhow!("Failed to get public inputs"))?;

    let mut rng = ChaChaRng::from_entropy();
    let proof = Groth16::<E, CircomReduction>::prove(params, circom, &mut rng)?;

    Ok((pi, proof))
}

pub fn verify<E: Pairing>(
    params: &VerifyingKey<E>,
    publics: &[E::ScalarField],
    proof: &Proof<E>,
) -> Result<bool> {
    Ok(Groth16::<E, CircomReduction>::verify(
        &params, publics, proof,
    )?)
}

#[inline]
fn parse_filed_to_token<F: PrimeField>(f: &F) -> Token {
    let bytes = f.into_bigint().to_bytes_be();
    Token::Uint(U256::from_big_endian(&bytes))
}

pub fn publics_proof_to_abi_bytes(
    publics: &[Bn254_Fr],
    proof: &Proof<Bn254>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut pi_token = vec![];
    for x in publics.iter() {
        pi_token.push(parse_filed_to_token(x));
    }

    let mut proof_token = vec![];
    let (ax, ay) = proof.a.xy().ok_or_else(|| anyhow!("Infallible point"))?;
    proof_token.push(parse_filed_to_token(ax));
    proof_token.push(parse_filed_to_token(ay));

    let (bx, by) = proof.b.xy().ok_or_else(|| anyhow!("Infallible point"))?;
    proof_token.push(parse_filed_to_token(&bx.c1));
    proof_token.push(parse_filed_to_token(&bx.c0));
    proof_token.push(parse_filed_to_token(&by.c1));
    proof_token.push(parse_filed_to_token(&by.c0));

    let (cx, cy) = proof.c.xy().ok_or_else(|| anyhow!("Infallible point"))?;
    proof_token.push(parse_filed_to_token(cx));
    proof_token.push(parse_filed_to_token(cy));

    let pi_bytes = encode(&pi_token);
    let proof_bytes = encode(&proof_token);

    Ok((pi_bytes, proof_bytes))
}

pub fn multiple_publics_from_abi_bytes(bytes: &[u8]) -> Result<Vec<Bn254_Fr>> {
    let mut input_tokens = decode(&[ParamType::Array(Box::new(ParamType::Uint(256)))], bytes)?;
    let tokens = input_tokens
        .pop()
        .ok_or_else(|| anyhow!("Infallible point"))?
        .into_array()
        .ok_or_else(|| anyhow!("Infallible point"))?;
    let mut publics = vec![];
    for token in tokens {
        let mut bytes = [0u8; 32];
        token.into_uint().unwrap().to_big_endian(&mut bytes);
        publics.push(Bn254_Fr::from_be_bytes_mod_order(&bytes));
    }

    Ok(publics)
}

pub fn multiple_proofs_to_abi_bytes(proofs: &[Proof<Bn254>]) -> Result<Vec<u8>> {
    let mut m_pr_token = vec![];
    for proof in proofs {
        let mut proof_token = vec![];
        let (ax, ay) = proof.a.xy().ok_or_else(|| anyhow!("Infallible point"))?;
        proof_token.push(parse_filed_to_token(ax));
        proof_token.push(parse_filed_to_token(ay));

        let (bx, by) = proof.b.xy().ok_or_else(|| anyhow!("Infallible point"))?;
        proof_token.push(parse_filed_to_token(&bx.c1));
        proof_token.push(parse_filed_to_token(&bx.c0));
        proof_token.push(parse_filed_to_token(&by.c1));
        proof_token.push(parse_filed_to_token(&by.c0));

        let (cx, cy) = proof.c.xy().ok_or_else(|| anyhow!("Infallible point"))?;
        proof_token.push(parse_filed_to_token(cx));
        proof_token.push(parse_filed_to_token(cy));

        m_pr_token.push(Token::FixedArray(proof_token));
    }
    let l_pr_token = Token::Array(m_pr_token);
    let proof_bytes = encode(&[l_pr_token]);

    Ok(proof_bytes)
}

pub fn proofs_to_raw_bytes(
    publics: &[Bls12_381_Fr],
    proof: &Proof<Bls12_381>,
) -> Result<(Vec<String>, [String; 3])> {
    let mut pi_token = vec![];
    for x in publics.iter() {
        pi_token.push(format!("{}", hex::encode(x.into_bigint().to_bytes_be())));
    }

    let mut pa_token = vec![];
    proof
        .a
        .serialize_compressed(&mut pa_token)
        .map_err(|_| anyhow!("Infallible point"))?;
    let pa = hex::encode(pa_token);

    let mut pb_token = vec![];
    proof
        .b
        .serialize_compressed(&mut pb_token)
        .map_err(|_| anyhow!("Infallible point"))?;
    let pb = hex::encode(pb_token);

    let mut pc_token = vec![];
    proof
        .c
        .serialize_compressed(&mut pc_token)
        .map_err(|_| anyhow!("Infallible point"))?;
    let pc = hex::encode(pc_token);

    Ok((pi_token, [pa, pb, pc]))
}
