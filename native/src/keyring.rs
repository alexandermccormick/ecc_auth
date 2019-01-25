use std::fs::{create_dir_all, write as write_file, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::sign::ed25519::PublicKey;
use sodiumoxide::crypto::sign::ed25519::SecretKey;

pub struct Keyring {
  public_key: PublicKey,
  secret_key: SecretKey,
}

impl Keyring {
  pub fn new(keyring_dir_path: &str) -> Keyring {
    let keyring_dir_path = Path::new(keyring_dir_path);
    match keyring_dir_path.exists() {
      true => Keyring::read_keys(keyring_dir_path),
      false => Keyring::create_keys(keyring_dir_path),
    }
  }

  fn create_keys(keyring_dir_path: &Path) -> Keyring {
    let (public_key, secret_key) = sign::gen_keypair();
    let mut keyring_path_buf = PathBuf::from(keyring_dir_path);

    match keyring_dir_path.exists() {
      false => {
        create_dir_all(&keyring_dir_path).ok();
      }
      true => match keyring_dir_path.is_dir() {
        false => panic!("Given path does not point to directory!!!"),
        true => {
          keyring_path_buf.push("pub.key");
          write_file(&keyring_path_buf, &public_key).ok();

          keyring_path_buf.set_file_name("sec.key");
          write_file(&keyring_path_buf, &secret_key.0[..]).ok();
        }
      },
    };

    Keyring {
      public_key,
      secret_key,
    }
  }

  fn read_keys(keyring_dir_path: &Path) -> Keyring {
    let mut keyring_path_buf = PathBuf::from(keyring_dir_path);

    keyring_path_buf.push("pub.key");

    let mut pub_key_file = File::open(&keyring_path_buf).unwrap();
    let mut pub_key_arr: [u8; 32] = [0; 32];
    pub_key_file.read_exact(&mut pub_key_arr).ok();
    let public_key = PublicKey(pub_key_arr);

    keyring_path_buf.set_file_name("sec.key");
    let mut sec_key_file = File::open(&keyring_path_buf).unwrap();
    let mut sec_key_arr: [u8; 64] = [0; 64];
    sec_key_file.read_exact(&mut sec_key_arr).ok();
    let secret_key = SecretKey(sec_key_arr);

    Keyring {
      public_key,
      secret_key,
    }
  }
}
