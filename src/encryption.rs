use std::ops::Mul;

use crate::{kzg::PowersOfTau, setup::AggregateKey};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    PrimeGroup,
};
use ark_serialize::*;
use ark_std::{UniformRand, Zero};

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct Ciphertext<E: Pairing> {
    pub gamma_g2: E::G2,
    pub sa1: [E::G1; 2],
    pub sa2: [E::G2; 6],
    pub enc_key: PairingOutput<E>, //key to be used for encapsulation
    pub t: usize,                  //threshold
}

impl<E: Pairing> Ciphertext<E> {
    pub fn new(
        gamma_g2: E::G2,
        sa1: [E::G1; 2],
        sa2: [E::G2; 6],
        enc_key: PairingOutput<E>,
        t: usize,
    ) -> Self {
        Ciphertext {
            gamma_g2,
            sa1,
            sa2,
            enc_key,
            t,
        }
    }
}

/// t is the threshold for encryption and apk is the aggregated public key
pub fn encrypt<E: Pairing>(
    apk: &AggregateKey<E>,
    t: usize,
    params: &PowersOfTau<E>,
) -> Ciphertext<E> {
    let mut rng = ark_std::test_rng();
    let gamma = E::ScalarField::rand(&mut rng);
    let gamma_g2 = params.powers_of_h[0] * gamma;

    let g = params.powers_of_g[0];
    let h = params.powers_of_h[0];

    let mut sa1 = [E::G1::generator(); 2];
    let mut sa2 = [E::G2::generator(); 6];

    let mut s: [E::ScalarField; 5] = [E::ScalarField::zero(); 5];

    s.iter_mut()
        .for_each(|s| *s = E::ScalarField::rand(&mut rng));

    // sa1[0] = s0*ask->C + s3*g^{tau^{t+1}} + s4*g// is it t or t+1
    sa1[0] = (apk.ask * s[0]) + (params.powers_of_g[t + 1] * s[3]) + (params.powers_of_g[0] * s[4]);

    // sa1[1] = s2*g  ->g
    sa1[1] = g * s[2];

    // sa2[0] = s0*h + s2*gamma_g2
    sa2[0] = (h * s[0]) + (gamma_g2 * s[2]);

    // sa2[1] = s0*z_g2-> this z_g2 ???->z(T)2
    sa2[1] = apk.z_g2 * s[0];

    // sa2[2] = s0*h^tau + s1*h^tau
    sa2[2] = params.powers_of_h[1] * (s[0] + s[1]);

    // sa2[3] = s1*h
    sa2[3] = h * s[1];

    // sa2[4] = s3*h
    sa2[4] = h * s[3];

    // sa2[5] = s4*h^{tau - omega^0}
    sa2[5] = (params.powers_of_h[1] + apk.h_minus1) * s[4];

    // enc_key = s4*e_gh
    let enc_key = apk.e_gh.mul(s[4]);


    Ciphertext {
        gamma_g2,
        sa1,
        sa2,
        enc_key,//CT3
        t,
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]pub struct cipher<E: Pairing> {
    pub gamma_g2: E::G2,
    pub sa1: [E::G1; 2],
    pub sa2: [E::G2; 6],
    // pub enc_key: PairingOutput<E>, //key to be used for encapsulation
    // pub t: usize, 
   pub ct3:  PairingOutput<E>              //threshold
}

impl<E: Pairing> cipher<E> {
    pub fn new(
        gamma_g2: E::G2,
        sa1: [E::G1; 2],
        sa2: [E::G2; 6],
        // enc_key: PairingOutput<E>,
        // t: usize,
        ct3:  PairingOutput<E>
    ) -> Self {
       cipher {
            gamma_g2,
            sa1,
            sa2,
            // enc_key,
            // t,
            ct3
        }
    }
}

/// t is the threshold for encryption and apk is the aggregated public key
/// ct3= s.b+msg 
/// ct3 = s4*e_gh + msg
pub fn encrypt1<E: Pairing>(
    apk: &AggregateKey<E>,
    t: usize,
    params: &PowersOfTau<E>,
    msg: E::ScalarField
) -> cipher<E> {
    let mut rng = ark_std::test_rng();
    let gamma = E::ScalarField::rand(&mut rng);
    let gamma_g2 = params.powers_of_h[0] * gamma;

    let g = params.powers_of_g[0];
    let h = params.powers_of_h[0];

    let mut sa1 = [E::G1::generator(); 2];
    let mut sa2 = [E::G2::generator(); 6];

    let mut s: [E::ScalarField; 5] = [E::ScalarField::zero(); 5];

    s.iter_mut()
        .for_each(|s| *s = E::ScalarField::rand(&mut rng));

    // sa1[0] = s0*ask + s3*g^{tau^{t+1}} + s4*g// todo is there t or t+1
    sa1[0] = (apk.ask * s[0]) + (params.powers_of_g[t + 1] * s[3]) + (params.powers_of_g[0] * s[4]);

    // sa1[1] = s2*g
    sa1[1] = g * s[2];

    // sa2[0] = s0*h + s2*gamma_g2
    sa2[0] = (h * s[0]) + (gamma_g2 * s[2]);

    // sa2[1] = s0*z_g2
    sa2[1] = apk.z_g2 * s[0];

    // sa2[2] = s0*h^tau + s1*h^tau
    sa2[2] = params.powers_of_h[1] * (s[0] + s[1]);

    // sa2[3] = s1*h
    sa2[3] = h * s[1];

    // sa2[4] = s3*h
    sa2[4] = h * s[3];

    // sa2[5] = s4*h^{tau - omega^0}
    sa2[5] = (params.powers_of_h[1] + apk.h_minus1) * s[4];

    // enc_key = s4*e_gh CT3= S.B+MSG -> S4+MSG
    let enc_key = apk.e_gh.mul(s[4]);
    //converting the msg into Gt element 
    let msg_out = apk.e_gh.mul(msg);
    let ct3 =enc_key + msg_out;
    println!("msg_out:{}",msg_out);
    cipher {
        gamma_g2,
        sa1,
        sa2,
       ct3
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        decryption::{decrypt,agg_dec}, kzg::KZG10, setup::{PublicKey, SecretKey}
    };
    use ark_poly::univariate::DensePolynomial;
    use ark_std::UniformRand;

    type E = ark_bls12_381::Bls12_381;
    type G1 = <E as Pairing>::G1;
    type G2 = <E as Pairing>::G2;
    type Fr = <E as Pairing>::ScalarField;
    type UniPoly381 = DensePolynomial<<E as Pairing>::ScalarField>;

    #[test]
    fn test_encryption() {
        let mut rng = ark_std::test_rng();
        let n = 8;
        let tau = Fr::rand(&mut rng);
        let params = KZG10::<E, UniPoly381>::setup(n, tau.clone()).unwrap();

        let mut sk: Vec<SecretKey<E>> = Vec::new();
        let mut pk: Vec<PublicKey<E>> = Vec::new();

        for i in 0..n {
            sk.push(SecretKey::<E>::new(&mut rng));
            pk.push(sk[i].get_pk(0, &params, n))
        }

        let ak = AggregateKey::<E>::new(pk, &params);// aggreate key
        let ct = encrypt::<E>(&ak, 2, &params);

        let mut ct_bytes = Vec::new();
        ct.serialize_compressed(&mut ct_bytes).unwrap();
        println!("Compressed ciphertext: {} bytes", ct_bytes.len());

        let mut g1_bytes = Vec::new();
        let mut g2_bytes = Vec::new();
        let mut e_gh_bytes = Vec::new();

        let g = G1::generator();
        let h = G2::generator();

        g.serialize_compressed(&mut g1_bytes).unwrap();
        h.serialize_compressed(&mut g2_bytes).unwrap();
        ak.e_gh.serialize_compressed(&mut e_gh_bytes).unwrap();

        println!("G1 len: {} bytes", g1_bytes.len());
        println!("G2 len: {} bytes", g2_bytes.len());
        println!("GT len: {} bytes", e_gh_bytes.len());
    }
     #[test]

    fn test_encrypt1(){
        let mut rng = ark_std::test_rng();
        let N = 1<<4;
        let t =N/2;
        let tau = Fr::rand(&mut rng);
        let params = KZG10::<E, UniPoly381>::setup(N, tau.clone()).unwrap();

        let mut sk: Vec<SecretKey<E>> = Vec::new();
        let mut pk: Vec<PublicKey<E>> = Vec::new();
        sk.push(SecretKey::<E>::new(&mut rng));
        sk[0].nullify();
        pk.push(sk[0].get_pk(0, &params, N));

        for i in 1..N{
            sk.push(SecretKey::<E>::new(&mut rng));
            pk.push(sk[i].get_pk(0, &params, N))
        }

        let ak = AggregateKey::<E>::new(pk, &params);
        let ct_i = encrypt::<E>(&ak, t, &params);
        // implementing the new encryption function
        let mut ct_i_bytes = Vec::new();
        ct_i.serialize_compressed(&mut ct_i_bytes).unwrap();
        println!("Compressed ciphertext: {} bytes", ct_i_bytes.len());

        let msg = Fr::rand(&mut rng);
        println!{"msg:{}",msg};
        let ct = encrypt1::<E>(&ak, t, &params,msg);
         let mut ct_bytes = Vec::new();
        ct.serialize_compressed(&mut ct_bytes).unwrap();
        println!("Compressed cipher: {} bytes", ct_bytes.len());

        let mut g1_bytes = Vec::new();
        let mut g2_bytes = Vec::new();
        let mut e_gh_bytes = Vec::new();

        let g = G1::generator();
        let h = G2::generator();

        g.serialize_compressed(&mut g1_bytes).unwrap();
        h.serialize_compressed(&mut g2_bytes).unwrap();
        ak.e_gh.serialize_compressed(&mut e_gh_bytes).unwrap();

        println!("G1 len: {} bytes", g1_bytes.len());
        println!("G2 len: {} bytes", g2_bytes.len());
        println!("GT len: {} bytes", e_gh_bytes.len());
        // have to put the parameter of the decrypt function and also have to convert the msg_out from Gt to a scalar field
        // need to check the partial decryption function
        let mut partial_decryptions: Vec<G2> = Vec::new();
        for i in 0..t + 1 {
            partial_decryptions.push(sk[i].partial_decryption(&ct_i));
        }
        for _ in t + 1..N {
            partial_decryptions.push(G2::zero());
        }

        // compute the decryption key
        let mut selector: Vec<bool> = Vec::new();
        for _ in 0..t + 1 {
            selector.push(true);
        }
        for _ in t + 1..N {
            selector.push(false);
        }
        println!("partial_decryptions:{:?}",partial_decryptions);
        let dec_key = agg_dec(&partial_decryptions, &ct_i, &selector, &ak, &params);
        // let msg_out = decrypt( &ct, &partial_decryptions, &ct_i,&selector, &ak, &params);
        // println!("msg_out:{}",msg_out);


    }
}
