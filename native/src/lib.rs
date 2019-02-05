#[macro_use]
extern crate neon;
extern crate neon_serde;
extern crate sodiumoxide;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate base64;

mod token;
mod keyring;

use token::Token;
use token::TokenHeader;
use token::TokenBody;
use token::TokenSignature;
use keyring::Keyring;

use neon::prelude::*;
use sodiumoxide::crypto::sign;
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
      let arg0 = cx.argument::<JsValue>(0)?;
      let token: Token = neon_serde::from_value(&mut cx, arg0)?;
      let sig = {
        let this = cx.this();
        let guard = &mut cx.lock();
        let auth = this.borrow(&guard);
        sign::sign_detached(&token.hashed().0, &auth.keyring.secret_key)
      };
      let sig_b64 = base64::encode_config(&sig, URL_SAFE_NO_PAD);
      let signed_token = [token.as_b64(), sig_b64].join(".");
      Ok(cx.string(signed_token).upcast())
    }

    method verify(mut cx) {
      let arg0: String = cx.argument::<JsString>(0)?.value();
      let token_parts: Vec<&str> = arg0.split(".").collect();
      let header = TokenHeader::from_b64(&token_parts[0]);
      let body = TokenBody::from_b64(&token_parts[1]);
      let sig = TokenSignature::from_b64(&token_parts[2]);
      let token = Token {
        header,
        body: body.value
      };
      let is_verified = {
        let this = cx.this();
        let guard = &mut cx.lock();
        let auth = this.borrow(&guard);
        sign::verify_detached(&sig.value, &token.hashed().0, &auth.keyring.public_key)
      };

      Ok(cx.boolean(is_verified).upcast())
    }
  }
}
register_module!(mut m, { m.export_class::<JsEccAuth>("EccAuth") });
