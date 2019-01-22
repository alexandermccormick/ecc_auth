use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthToken {
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