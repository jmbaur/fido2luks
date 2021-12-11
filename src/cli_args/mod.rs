use crate::error::*;
use crate::*;
use ring::digest;

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq)]
pub enum SecretInput {
    AskPassword,
    String(String),
    File { path: PathBuf },
}

impl Default for SecretInput {
    fn default() -> Self {
        SecretInput::AskPassword
    }
}

impl From<&str> for SecretInput {
    fn from(s: &str) -> Self {
        let mut parts = s.split(':');
        match parts.next() {
            Some("ask") | Some("Ask") => SecretInput::AskPassword,
            Some("file") => SecretInput::File {
                path: parts.collect::<Vec<_>>().join(":").into(),
            },
            Some("string") => SecretInput::String(parts.collect::<Vec<_>>().join(":")),
            _ => Self::default(),
        }
    }
}

impl FromStr for SecretInput {
    type Err = Fido2LuksError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(s))
    }
}

impl fmt::Display for SecretInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&match self {
            SecretInput::AskPassword => "ask".to_string(),
            SecretInput::String(s) => ["string", s].join(":"),
            SecretInput::File { path } => ["file", path.display().to_string().as_str()].join(":"),
        })
    }
}

impl SecretInput {
    pub fn obtain_string(&self, password_helper: &PasswordHelper) -> Fido2LuksResult<String> {
        Ok(String::from_utf8(self.obtain(password_helper)?)?)
    }

    pub fn obtain(&self, password_helper: &PasswordHelper) -> Fido2LuksResult<Vec<u8>> {
        let mut secret = Vec::new();
        match self {
            SecretInput::File { path } => {
                //TODO: replace with try_blocks
                let mut do_io = || File::open(path)?.read_to_end(&mut secret);
                do_io().map_err(|cause| Fido2LuksError::KeyfileError { cause })?;
            }
            SecretInput::AskPassword => {
                secret.extend_from_slice(password_helper.obtain()?.as_bytes())
            }

            SecretInput::String(s) => secret.extend_from_slice(s.as_bytes()),
        }
        Ok(secret)
    }

    pub fn obtain_sha256(&self, password_helper: &PasswordHelper) -> Fido2LuksResult<[u8; 32]> {
        let mut digest = digest::Context::new(&digest::SHA256);
        match self {
            SecretInput::File { path } => {
                let mut do_io = || {
                    let mut reader = File::open(path)?;
                    let mut buf = [0u8; 512];
                    loop {
                        let red = reader.read(&mut buf)?;
                        digest.update(&buf[0..red]);
                        if red == 0 {
                            break;
                        }
                    }
                    Ok(())
                };
                do_io().map_err(|cause| Fido2LuksError::KeyfileError { cause })?;
            }
            _ => digest.update(self.obtain(password_helper)?.as_slice()),
        }
        let mut salt = [0u8; 32];
        salt.as_mut().copy_from_slice(digest.finish().as_ref());
        Ok(salt)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordHelper {
    Script(String),
    #[allow(dead_code)]
    Systemd,
    Stdin,
}

impl Default for PasswordHelper {
    fn default() -> Self {
        PasswordHelper::Script(
            "/usr/bin/env systemd-ask-password 'Please enter second factor for LUKS disk encryption!'"
                .into(),
        )
    }
}

impl From<&str> for PasswordHelper {
    fn from(s: &str) -> Self {
        match s {
            "stdin" => PasswordHelper::Stdin,
            s => PasswordHelper::Script(s.into()),
        }
    }
}

impl FromStr for PasswordHelper {
    type Err = Fido2LuksError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(s))
    }
}

impl fmt::Display for PasswordHelper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&match self {
            PasswordHelper::Stdin => "stdin".to_string(),
            PasswordHelper::Systemd => "systemd".to_string(),
            PasswordHelper::Script(path) => path.clone(),
        })
    }
}

impl PasswordHelper {
    pub fn obtain(&self) -> Fido2LuksResult<String> {
        use PasswordHelper::*;
        match self {
            Systemd => unimplemented!(),
            Stdin => Ok(util::read_password("Password", true)?),
            Script(password_helper) => {
                let password = Command::new("sh")
                    .arg("-c")
                    .arg(&password_helper)
                    .output()
                    .map_err(|e| Fido2LuksError::AskPassError {
                        cause: error::AskPassError::IO(e),
                    })?
                    .stdout;
                Ok(String::from_utf8(password)?.trim().to_owned())
            }
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn input_salt_from_str() {
        assert_eq!(
            "file:/tmp/abc".parse::<SecretInput>().unwrap(),
            SecretInput::File {
                path: "/tmp/abc".into()
            }
        );
        assert_eq!(
            "string:abc".parse::<SecretInput>().unwrap(),
            SecretInput::String("abc".into())
        );
        assert_eq!(
            "ask".parse::<SecretInput>().unwrap(),
            SecretInput::AskPassword
        );
        assert_eq!(
            "lol".parse::<SecretInput>().unwrap(),
            SecretInput::default()
        );
    }

    #[test]
    fn input_salt_obtain() {
        assert_eq!(
            SecretInput::String("abc".into())
                .obtain_sha256(&PasswordHelper::Stdin)
                .unwrap(),
            [
                186, 120, 22, 191, 143, 1, 207, 234, 65, 65, 64, 222, 93, 174, 34, 35, 176, 3, 97,
                163, 150, 23, 122, 156, 180, 16, 255, 97, 242, 0, 21, 173
            ]
        )
    }
}
use std::fmt::{Display, Error, Formatter};
use std::path::PathBuf;
use std::str::FromStr;
use structopt::clap::AppSettings;
use structopt::StructOpt;

mod config;

pub use config::*;

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct HexEncoded(pub Vec<u8>);

impl Display for HexEncoded {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.write_str(&hex::encode(&self.0))
    }
}

impl AsRef<[u8]> for HexEncoded {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl FromStr for HexEncoded {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(HexEncoded(hex::decode(s)?))
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct CommaSeparated<T: FromStr + Display>(pub Vec<T>);

impl<T: Display + FromStr> Display for CommaSeparated<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        for i in &self.0 {
            f.write_str(&i.to_string())?;
            f.write_str(",")?;
        }
        Ok(())
    }
}

impl<T: Display + FromStr> FromStr for CommaSeparated<T> {
    type Err = <T as FromStr>::Err;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(CommaSeparated(
            s.split(',')
                .map(|part| <T as FromStr>::from_str(part))
                .collect::<Result<Vec<_>, _>>()?,
        ))
    }
}

#[derive(Debug, StructOpt)]
pub struct Credentials {
    /// FIDO credential ids, separated by ',' generate using fido2luks credential
    #[structopt(name = "credential-id", env = "FIDO2LUKS_CREDENTIAL_ID")]
    pub ids: CommaSeparated<HexEncoded>,
}

#[derive(Debug, StructOpt)]
pub struct AuthenticatorParameters {
    /// Request a PIN to unlock the authenticator
    #[structopt(short = "P", long = "pin")]
    pub pin: bool,

    /// Location to read PIN from
    #[structopt(long = "pin-source", env = "FIDO2LUKS_PIN_SOURCE")]
    pub pin_source: Option<PathBuf>,

    /// Await for an authenticator to be connected, timeout after n seconds
    #[structopt(
        long = "await-dev",
        name = "await-dev",
        env = "FIDO2LUKS_DEVICE_AWAIT",
        default_value = "15"
    )]
    pub await_time: u64,
}

#[derive(Debug, StructOpt)]
pub struct LuksParameters {
    #[structopt(env = "FIDO2LUKS_DEVICE")]
    pub device: PathBuf,

    /// Try to unlock the device using a specifc keyslot, ignore all other slots
    #[structopt(long = "slot", env = "FIDO2LUKS_DEVICE_SLOT")]
    pub slot: Option<u32>,
}

#[derive(Debug, StructOpt, Clone)]
pub struct LuksModParameters {
    /// Number of milliseconds required to derive the volume decryption key
    /// Defaults to 10ms when using an authenticator or the default by cryptsetup when using a password
    #[structopt(long = "kdf-time", name = "kdf-time")]
    pub kdf_time: Option<u64>,
}

#[derive(Debug, StructOpt)]
pub struct SecretParameters {
    /// Salt for secret generation, defaults to 'ask'
    ///
    /// Options:{n}
    ///  - ask              : Prompt user using password helper{n}
    ///  - file:<PATH>      : Will read <FILE>{n}
    ///  - string:<STRING>  : Will use <STRING>, which will be handled like a password provided to the 'ask' option{n}
    #[structopt(
        name = "salt",
        long = "salt",
        env = "FIDO2LUKS_SALT",
        default_value = "ask"
    )]
    pub salt: SecretInput,
    /// Script used to obtain passwords, overridden by --interactive flag
    #[structopt(
        name = "password-helper",
        env = "FIDO2LUKS_PASSWORD_HELPER",
        default_value = "/usr/bin/env systemd-ask-password 'Please enter second factor for LUKS disk encryption!'"
    )]
    pub password_helper: PasswordHelper,
}
#[derive(Debug, StructOpt)]
pub struct Args {
    /// Request passwords via Stdin instead of using the password helper
    #[structopt(short = "i", long = "interactive")]
    pub interactive: bool,
    #[structopt(subcommand)]
    pub command: Command,
}

#[derive(Debug, StructOpt, Clone)]
pub struct OtherSecret {
    /// Use a keyfile instead of a password
    #[structopt(short = "d", long = "keyfile", conflicts_with = "fido_device")]
    pub keyfile: Option<PathBuf>,
    /// Use another fido device instead of a password
    /// Note: this requires for the credential fot the other device to be passed as argument as well
    #[structopt(short = "f", long = "fido-device", conflicts_with = "keyfile")]
    pub fido_device: bool,
}

#[derive(Debug, StructOpt)]
pub enum Command {
    #[structopt(name = "print-secret")]
    PrintSecret {
        /// Prints the secret as binary instead of hex encoded
        #[structopt(short = "b", long = "bin")]
        binary: bool,
        #[structopt(flatten)]
        credentials: Credentials,
        #[structopt(flatten)]
        authenticator: AuthenticatorParameters,
        #[structopt(flatten)]
        secret: SecretParameters,
    },
    /// Adds a generated key to the specified LUKS device
    #[structopt(name = "add-key")]
    AddKey {
        #[structopt(flatten)]
        luks: LuksParameters,
        #[structopt(flatten)]
        credentials: Credentials,
        #[structopt(flatten)]
        authenticator: AuthenticatorParameters,
        #[structopt(flatten)]
        secret: SecretParameters,
        /// Will wipe all other keys
        #[structopt(short = "e", long = "exclusive")]
        exclusive: bool,
        /// Will add an token to your LUKS 2 header, including the credential id
        #[structopt(short = "t", long = "token")]
        token: bool,
        #[structopt(flatten)]
        existing_secret: OtherSecret,
        #[structopt(flatten)]
        luks_mod: LuksModParameters,
    },
    /// Replace a previously added key with a password
    #[structopt(name = "replace-key")]
    ReplaceKey {
        #[structopt(flatten)]
        luks: LuksParameters,
        #[structopt(flatten)]
        credentials: Credentials,
        #[structopt(flatten)]
        authenticator: AuthenticatorParameters,
        #[structopt(flatten)]
        secret: SecretParameters,
        /// Add the password and keep the key
        #[structopt(short = "a", long = "add-password")]
        add_password: bool,
        /// Will add an token to your LUKS 2 header, including the credential id
        #[structopt(short = "t", long = "token")]
        token: bool,
        #[structopt(flatten)]
        replacement: OtherSecret,
        #[structopt(flatten)]
        luks_mod: LuksModParameters,
    },
    /// Open the LUKS device
    #[structopt(name = "open")]
    Open {
        #[structopt(flatten)]
        luks: LuksParameters,
        #[structopt(env = "FIDO2LUKS_MAPPER_NAME")]
        name: String,
        #[structopt(flatten)]
        credentials: Credentials,
        #[structopt(flatten)]
        authenticator: AuthenticatorParameters,
        #[structopt(flatten)]
        secret: SecretParameters,
        #[structopt(short = "r", long = "max-retries", default_value = "0")]
        retries: i32,
    },
    /// Open the LUKS device using credentials embedded in the LUKS 2 header
    #[structopt(name = "open-token")]
    OpenToken {
        #[structopt(flatten)]
        luks: LuksParameters,
        #[structopt(env = "FIDO2LUKS_MAPPER_NAME")]
        name: String,
        #[structopt(flatten)]
        authenticator: AuthenticatorParameters,
        #[structopt(flatten)]
        secret: SecretParameters,
        #[structopt(short = "r", long = "max-retries", default_value = "0")]
        retries: i32,
    },
    /// Generate a new FIDO credential
    #[structopt(name = "credential")]
    Credential {
        #[structopt(flatten)]
        authenticator: AuthenticatorParameters,
        /// Name to be displayed on the authenticator display
        #[structopt(env = "FIDO2LUKS_CREDENTIAL_NAME", default_value = "fido2luks")]
        name: String,
    },
    /// Check if an authenticator is connected
    #[structopt(name = "connected")]
    Connected,
    Token(TokenCommand),
    /// Generate bash completion scripts
    #[structopt(name = "completions", setting = AppSettings::Hidden)]
    GenerateCompletions {
        /// Shell to generate completions for: bash, fish
        #[structopt(possible_values = &["bash", "fish"])]
        shell: String,
        out_dir: PathBuf,
    },
}

///LUKS2 token related operations
#[derive(Debug, StructOpt)]
pub enum TokenCommand {
    /// List all tokens associated with the specified device
    List {
        #[structopt(env = "FIDO2LUKS_DEVICE")]
        device: PathBuf,
        /// Dump all credentials as CSV
        #[structopt(long = "csv")]
        csv: bool,
    },
    /// Add credential to a keyslot
    Add {
        #[structopt(env = "FIDO2LUKS_DEVICE")]
        device: PathBuf,
        #[structopt(flatten)]
        credentials: Credentials,
        /// Slot to which the credentials will be added
        #[structopt(long = "slot", env = "FIDO2LUKS_DEVICE_SLOT")]
        slot: u32,
    },
    /// Remove credentials from token(s)
    Remove {
        #[structopt(env = "FIDO2LUKS_DEVICE")]
        device: PathBuf,
        #[structopt(flatten)]
        credentials: Credentials,
        /// Token from which the credentials will be removed
        #[structopt(long = "token")]
        token_id: Option<u32>,
    },
    /// Remove all unassigned tokens
    GC {
        #[structopt(env = "FIDO2LUKS_DEVICE")]
        device: PathBuf,
    },
}
