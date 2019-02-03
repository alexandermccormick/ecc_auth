#[macro_use]
extern crate neon;
extern crate neon_serde;
extern crate sodiumoxide;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate bincode;
extern crate base64;

mod token;
mod keyring;

use token::Token;
use keyring::Keyring;

use neon::prelude::*;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::hash::sha512;
use bincode::serialize;
use base64::URL_SAFE_NO_PAD;

pub struct EccAuth {
  keyring: Keyring
}

impl EccAuth {
  fn new(keyring_dir_path: &str) -> EccAuth {
    let keyring = Keyring::new(&keyring_dir_path);

    EccAuth { keyring }
  }
}

declare_types! {
  pub class JsEccAuth for EccAuth {
    init(mut cx) {
      let keyring_dir_path: Handle<JsString> = cx.argument::<JsString>(0)?;
      let ecc_auth = EccAuth::new(&keyring_dir_path.value());

      Ok(ecc_auth)
    }

    method sign(mut cx) {
      let raw_obj = cx.argument::<JsValue>(0)?;
      let token: Token = neon_serde::from_value(&mut cx, raw_obj)?;

      let header = serde_json::to_string(&token.header).ok().expect("Could not stringify header!!!");
      let body = serde_json::to_string(&token.body).ok().expect("Could not stringify body!!!");
      let b64_header = base64::encode_config(&header, URL_SAFE_NO_PAD);
      let b64_body = base64::encode_config(&body, URL_SAFE_NO_PAD);
      let b64_token = [b64_header, b64_body].join(".");

      let sig = {
        let this = cx.this();
        let guard = &mut cx.lock();
        let auth = this.borrow(&guard);
        let token_hash = sha512::hash(&b64_token.as_bytes());
        sign::sign_detached(&token_hash.0, &auth.keyring.secret_key)
      };

      let b64_sig = base64::encode_config(&sig, URL_SAFE_NO_PAD);
      let signed_token = [b64_token, b64_sig].join(".");
      Ok(cx.string(signed_token).upcast())
    }

    // method showKey(mut cx) {
    //   // just an example of how to return data
    //   let pk = {
    //     let this = cx.this();
    //     let guard = &mut cx.lock();
    //     let ecc_auth = this.borrow(&guard);
    //     ecc_auth.keyring.public_key
    //   };
    //   println!("{:?}", pk);
    //   Ok(cx.boolean(true).upcast())
    // }
  }
}
register_module!(mut m, { m.export_class::<JsEccAuth>("EccAuth") });
