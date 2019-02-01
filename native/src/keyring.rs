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
    match &keyring_path_buf.exists() {
      true => Keyring::read_keys(&mut keyring_path_buf),
      false => {
        let (public_key, secret_key) = Keyring::create_keys(&mut keyring_path_buf);

        Keyring {
          public_key,
          secret_key
        }
      },
    }
  }

  fn create_keys(keyring_path_buf: &mut PathBuf) -> (PublicKey, SecretKey) {
    let (public_key, secret_key) = sign::gen_keypair();

    match keyring_path_buf.is_dir() {
      true => (),
      false => create_dir_all(&keyring_path_buf).ok().expect("Could not create path!!!"),
    };

    Keyring::write_keys(&public_key.0, &secret_key.0[..], keyring_path_buf);

    (public_key, secret_key)
  }

  fn write_keys(pk: &[u8; 32], sk: &[u8], keyring_path_buf: &mut PathBuf) {
    match keyring_path_buf.is_dir() {
      false => panic!("Given path does not point to directory!!!"),
      true => {
        keyring_path_buf.push("public.key");
        write_file(&keyring_path_buf, pk).ok();

        keyring_path_buf.set_file_name("secret.key");
        write_file(&keyring_path_buf, sk).ok();
      }
    }
  }

  // TODO: check for keys in dir first
  fn read_keys(keyring_path_buf: &mut PathBuf) -> Keyring {
    match keyring_path_buf.is_dir() {
      true => {
        let public_key = Keyring::load_pub_key(keyring_path_buf);
        let secret_key = Keyring::load_secret_key(keyring_path_buf);

        Keyring {
          public_key,
          secret_key,
        }
      },
      false => panic!("Given PATH does not lead to directory")
    }
  }

  fn load_pub_key(keyring_path_buf: &mut PathBuf) -> PublicKey {
    keyring_path_buf.push("public.key");
    match keyring_path_buf.is_file() {
      true => {
        let mut pub_key_file = File::open(&keyring_path_buf).unwrap();
        let mut pub_key_arr: [u8; 32] = [0; 32];
        pub_key_file.read_exact(&mut pub_key_arr).ok();
        PublicKey(pub_key_arr)
      },
      false => {
        keyring_path_buf.pop();
        let (public_key, _secret_key) = Keyring::create_keys(keyring_path_buf);
        public_key
      }
    }
  }

  fn load_secret_key(keyring_path_buf: &mut PathBuf) -> SecretKey {
    keyring_path_buf.set_file_name("secret.key");
    match keyring_path_buf.is_file() {
      true => {
      let mut secret_key_file = File::open(&keyring_path_buf).unwrap();
      let mut secret_key_arr: [u8; 64] = [0; 64];
      secret_key_file.read_exact(&mut secret_key_arr).ok();
      SecretKey(secret_key_arr)
      },
      false => {
        keyring_path_buf.pop();
        let (_public_key, secret_key) = Keyring::create_keys(keyring_path_buf);
        secret_key
      }
    }
  }
}
