use std::cmp::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};
use neon::prelude::*;

#[derive(Serialize, Deserialize, Debug)]
pub struct Token {
  pub header: TokenHeader,
  pub body: serde_json::Value,
  pub signature: Option<String>
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

impl Token {
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

// #[derive(Serialize, Deserialize, Debug)]
// struct TokenSignature;
