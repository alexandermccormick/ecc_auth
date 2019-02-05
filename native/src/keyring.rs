use std::fs::{create_dir_all, write as write_file, File};
use std::io::Read;
use std::path::PathBuf;

use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::sign::ed25519::PublicKey;
use sodiumoxide::crypto::sign::ed25519::SecretKey;

pub struct Keyring {
  pub public_key: PublicKey,
  pub secret_key: SecretKey,
}

impl Keyring {
  pub fn new(keyring_path_buf: &str) -> Keyring {
    let mut keyring_path_buf = PathBuf::from(keyring_path_buf);
    match (keyring_path_buf.exists(), keyring_path_buf.is_dir()) {
      (true, true) => Keyring::read_keys(&mut keyring_path_buf),
      (false, false) => {
        create_dir_all(&keyring_path_buf).ok().expect("Could not create path for keys!!!");
        Keyring::create_keys(&mut keyring_path_buf)
      },
      (true, false) => panic!("Given PATH does not lead to directory!!!"),
      (false, true) => panic!("This shouldn't be possible! Given PATH does not exist, but is directory!!!")
    }
  }

  fn create_keys(keyring_path_buf: &mut PathBuf) -> Keyring {
    let (public_key, secret_key) = sign::gen_keypair();

    Keyring::write_public_key(&public_key.0, keyring_path_buf);
    Keyring::write_secret_key(&secret_key.0[..], keyring_path_buf);

    Keyring {
      public_key,
      secret_key
    }
  }

  fn write_public_key(public_key: &[u8; 32], keyring_path_buf: &mut PathBuf) {
    keyring_path_buf.push("public.key");
    write_file(&keyring_path_buf, public_key).ok();
    keyring_path_buf.pop();
  }

  fn write_secret_key(secret_key: &[u8], keyring_path_buf: &mut PathBuf) {
    keyring_path_buf.push("secret.key");
    write_file(&keyring_path_buf, secret_key).ok();
    keyring_path_buf.pop();
  }

  fn read_keys(keyring_path_buf: &mut PathBuf) -> Keyring {
    match Keyring::contains_keys(keyring_path_buf) {
      true => {
        let public_key = Keyring::load_pub_key(keyring_path_buf);
        let secret_key = Keyring::load_secret_key(keyring_path_buf);

        Keyring {
          public_key,
          secret_key,
        }
      },
      false => Keyring::create_keys(keyring_path_buf)
    }
  }
  fn contains_keys(keyring_path_buf: &mut PathBuf) -> bool {
    keyring_path_buf.push("public.key");
    let has_public = match (keyring_path_buf.exists(), keyring_path_buf.is_file()) {
      (true, true) => true,
      (false, false) => false,
      (true, false) => panic!("Given PUBLIC_KEY_PATH does not lead to file!!!"),
      (false, true) => panic!("This shouldn't be possible! Given PATH does not exist, but is file!!!")
    };
    keyring_path_buf.set_file_name("secret.key");
    let has_secret = match (keyring_path_buf.exists(), keyring_path_buf.is_file()) {
      (true, true) => true,
      (false, false) => false,
      (true, false) => panic!("Given SECRET_KEY_PATH does not lead to file!!!"),
      (false, true) => panic!("This shouldn't be possible! Given PATH does not exist, but is file!!!")
    };
    keyring_path_buf.pop();

    match (&has_public, &has_secret) {
      (true, true) => true,
      (false, true) => panic!("Missing public key!!!"),
      (true, false) => panic!("Missing secret key!!!"),
      (false, false) => false
    }
  }

  fn load_pub_key(keyring_path_buf: &mut PathBuf) -> PublicKey {
    keyring_path_buf.push("public.key");
    let mut pub_key_file = File::open(&keyring_path_buf).expect("Could not load public key!!!");
    let mut pub_key_arr: [u8; 32] = [0; 32];
    pub_key_file.read_exact(&mut pub_key_arr).ok();
    keyring_path_buf.pop();
    PublicKey(pub_key_arr)
  }

  fn load_secret_key(keyring_path_buf: &mut PathBuf) -> SecretKey {
    keyring_path_buf.push("secret.key");
    let mut secret_key_file = File::open(&keyring_path_buf).expect("Could not load secret key!!!");
    let mut secret_key_arr: [u8; 64] = [0; 64];
    secret_key_file.read_exact(&mut secret_key_arr).ok();
    keyring_path_buf.pop();
    SecretKey(secret_key_arr)
  }
}
