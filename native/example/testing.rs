#[macro_use]
extern crate neon;
// #[macro_use]
extern crate neon_serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate sodiumoxide;

use neon::prelude::*;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::SecretKey;

use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Debug)]
struct EccAuth {
    name: String,
}

impl EccAuth {}

fn init_ecc_auth(mut cx: FunctionContext) -> JsResult<JsValue> {
    let arg0 = cx.argument::<JsValue>(0)?;

    let token: AuthToken = neon_serde::from_value(&mut cx, arg0)?;
    println!("OBJ from JS: {:?}", token);



    println!("{:?}", &token.header.is_expired());

    let js_obj = neon_serde::to_value(&mut cx, &token)?;

    Ok(js_obj)
}

pub struct AuthKeyring {
    open_pk: PublicKey,
    open_sk: SecretKey,
    seal_pk: PublicKey,
    seal_sk: SecretKey,
}

impl AuthKeyring {
    fn new() -> AuthKeyring {
        let (open_pk, seal_sk) = box_::gen_keypair();
        let (seal_pk, open_sk) = box_::gen_keypair();

        AuthKeyring {
            open_pk,
            open_sk,
            seal_pk,
            seal_sk
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct AuthToken {
    header: AuthTokenHeader,
    body: serde_json::Value,
    // signature: Option<AuthTokenSignature>
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct AuthTokenHeader {
    // Issuer
    iss: String,
    // Subject
    sub: Option<String>,
    // Audience
    aud: Option<String>,
    // Expiration
    exp: String,
    // Not Before
    nbf: Option<String>,
    // Issued at
    iat: u64,

}

impl AuthTokenHeader {
    fn is_expired(&self) -> bool {
        let exp_field: &String = &self.exp.clone();
        let parts: Vec<&str> = exp_field.split(" ").collect();
        let exp_time: u64 = {
            let ms: u64 = match parts[1] {
                "s" => parts[0].parse::<u64>().unwrap() * 1000,
                "m" => parts[0].parse::<u64>().unwrap() * 60000,
                "h" => parts[0].parse::<u64>().unwrap() * 3600000,
                "d" => parts[0].parse::<u64>().unwrap() * 86400000,
                _ => 0,
            };
            ms + &self.iat
        };
        let today = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        if exp_time > today as u64 {
            true
        } else {
            false
        }
    }
}

// #[derive(Serialize, Deserialize, Debug)]
// struct AuthTokenSignature;

register_module!(mut m, { m.export_function("initEccAuth", init_ecc_auth) });
