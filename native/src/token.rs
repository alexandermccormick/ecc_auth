use std::cmp::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};
// use sodiumoxide::crypto::sign;
// use sodiumoxide::crypto::sign::Signature;
use sodiumoxide::crypto::hash::sha512;
use sodiumoxide::crypto::hash::Digest;
use sodiumoxide::crypto::sign::Signature;

use base64::URL_SAFE_NO_PAD;

trait B64 {
  fn as_b64(&self) -> String;
}

impl B64 for serde_json::Value {
  fn as_b64(&self) -> String {
    let str_self = serde_json::to_string(&self).ok().expect("Could not stringify header!!!");
    base64::encode_config(&str_self, URL_SAFE_NO_PAD)
  }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Token {
  pub header: TokenHeader,
  pub body: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TokenHeader {
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

#[derive(Serialize, Deserialize, Debug)]
pub struct TokenBody {
  pub value: serde_json::Value
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TokenSignature {
  pub value: Signature
}

impl Token {
  pub fn as_b64(&self) -> String {
    [self.header.as_b64(), self.body.as_b64()].join(".")
  }

  pub fn hashed(&self) -> Digest {
    sha512::hash(self.as_b64().as_bytes())
  }

  pub fn is_expired(&self) -> bool {
    let exp_field: &String = &self.header.exp;
    let parts: Vec<&str> = exp_field.split(" ").collect();
    let exp_time: u64 = {
      let ms: u64 = match parts[1] {
        "s" => parts[0].parse::<u64>().unwrap() * 1000,
        "m" => parts[0].parse::<u64>().unwrap() * 60000,
        "h" => parts[0].parse::<u64>().unwrap() * 3600000,
        "d" => parts[0].parse::<u64>().unwrap() * 86400000,
        _ => 0,
      };
      ms + &self.header.iat
    };
    let today: u64 = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap()
      .as_millis() as u64;

    match exp_time.cmp(&today) {
      Ordering::Greater => false,
      Ordering::Equal => true,
      Ordering::Less => true,
    }
  }
}

impl TokenHeader {
  pub fn as_b64(&self) -> String {
    let str_self = serde_json::to_string(&self).ok().expect("Could not stringify header!!!");
    base64::encode_config(&str_self, URL_SAFE_NO_PAD)
  }
  pub fn from_b64(header_b64: &str) -> TokenHeader {
      let header_vec = base64::decode_config(header_b64, URL_SAFE_NO_PAD).ok().expect("Could not decode header!!!");
      let header_str = String::from_utf8(header_vec).ok().expect("Could not convert header_vec to string");
      serde_json::from_str(&header_str).ok().expect("Could not parse token header!!!")
  }
}

impl TokenBody {
  pub fn from_b64(body_b64: &str) -> TokenBody {
    let body_vec = base64::decode_config(body_b64, URL_SAFE_NO_PAD).ok().expect("Could not parse token body!!!");
    let body_str = String::from_utf8(body_vec).ok().expect("Could not convert body_vec to string");
    let value: serde_json::Value = serde_json::from_str(&body_str).ok().expect("Could not parse token!!!");
    TokenBody {
      value
    }
  }
}

impl TokenSignature {
  pub fn from_b64(sig_b64: &str) -> TokenSignature {
    let sig_vec = base64::decode_config(&sig_b64, URL_SAFE_NO_PAD).ok().expect("Could not parse token signature!!!");
    let mut arr = [0u8;64];
    for (place, element) in arr.iter_mut().zip(sig_vec.iter()) {
        *place = *element;
    }
    let sig = Signature(arr);
    TokenSignature {
      value: sig
    }
  }
}
