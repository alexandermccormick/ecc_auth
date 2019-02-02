#[macro_use]
extern crate neon;
extern crate neon_serde;
extern crate sodiumoxide;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

mod auth_token;
mod keyring;

use auth_token::AuthToken;
use keyring::Keyring;

use neon::prelude::*;

pub struct EccAuth {
  keyring: Keyring
}

impl EccAuth {
  fn new(keyring_dir_path: &str) -> EccAuth {
    let keyring = Keyring::new(&keyring_dir_path);

    EccAuth { keyring }
  }
  
  fn sign(raw_token: AuthToken) -> () {}
}

declare_types! {
  pub class JsEccAuth for EccAuth {
    init(mut cx) {
      let keyring_dir_path: Handle<JsString> = cx.argument::<JsString>(0)?;
      let ecc_auth = EccAuth::new(&keyring_dir_path.value());

      Ok(ecc_auth)
    }

    method sign(mut cx) {
      let token_obj = cx.argument::<JsValue>(0)?;
      let raw_token: AuthToken = neon_serde::from_value(&mut cx, token_obj)?;
      
      println!("Token is expired: {:?}", raw_token.is_expired());
      println!("{:?}", raw_token);


      Ok(cx.boolean(true).upcast())
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
