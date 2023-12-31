use libpep::*;
use libpep::simple::*;
use commandy_macros::*;
use rand_core::OsRng;

// https://stackoverflow.com/questions/52987181/how-can-i-convert-a-hex-string-to-a-u8-slice
use std::{fmt::Write, num::ParseIntError};
pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

#[derive(Command,Debug,Default)]
#[command("generate-global-keys")]
#[description("Outputs a public global key and a secret global key (use once).")]
struct GenerateGlobalKeys {
}

#[derive(Command,Debug,Default)]
#[command("generate-pseudonym")]
#[description("Generates an encrypted global pseudonym.")]
struct GenerateEncryptedPseudonym {
    #[positional("identity global-public-key",2,2)]
    args: Vec<String>,
}

#[derive(Command,Debug,Default)]
#[command("convert-to-local-pseudonym")]
#[description("Converts a global encrypted pseudonym to a local encrypted pseudonym, decryptable by anybody that has the secret key as generated by make-local-decryption-key with the same decryption-context. The pseudonyms will be stable if the same pseudonymisation context is given. Server secret is a random string (so the pseudonymisation and decryption factors are not guessable).")]
struct ConvertToLocalPseudonym{
    #[positional("global-pseudonym server-secret decryption-context pseudonimisation-context",4,4)]
    args: Vec<String>,
}

#[derive(Command,Debug,Default)]
#[command("make-local-decryption-key")]
#[description("Creates a key that a party can use to decrypt an encrypted local pseudonym.")]
struct MakeLocalDecryptionKey {
    #[positional("global-secret-key server-secret decryption-context",3,3)]
    args: Vec<String>,
}

#[derive(Command,Debug,Default)]
#[command("decrypt-local-pseudonym")]
#[description("Decrypts the local encrypted pseudonym with a local decryption key as generated by make-local-decryption-key.")]
struct DecryptLocalPseudonym {
    #[positional("pseudonym local-decryption-key",2,2)]
    args: Vec<String>,
}

#[derive(Command,Debug,Default)]
#[command("rerandomize-pseudonym")]
#[description("Rerandomizes an encrypted pseudonym, that can be both global or local.")]
struct RerandomizePseudonym {
    #[positional("pseudonym",1,1)]
    args: Vec<String>,
}

#[derive(Command,Debug)]
enum Sub {
    GenerateGlobalKeys(GenerateGlobalKeys),
    GenerateEncryptedPseudonym(GenerateEncryptedPseudonym),
    ConvertToLocalPseudonym(ConvertToLocalPseudonym),
    MakeLocalDecryptionKey(MakeLocalDecryptionKey),
    DecryptLocalPseudonym(DecryptLocalPseudonym),
    RerandomizePseudonym(RerandomizePseudonym),
}

#[derive(Command,Debug,Default)]
#[description("operations on PEP pseudonyms")]
#[program("peppy")] // can have an argument, outputs man-page + shell completion
/// Perform operations on PEP pseudonyms: generate new system keys, generate an encrypted
/// global PEP pseudonym, convert an encrypted global PEP pseudonym to an encrypted local PEP
/// pseudonym, and decrypt a encrypted local PEP pseudonym to a (stable) local PEP pseudonym.
struct Options {
    #[subcommands()]
    subcommand: Option<Sub>,
}

fn main() {
    let mut rng = OsRng;
    let options : Options = commandy::parse_args();
    match options.subcommand {
        Some(Sub::GenerateGlobalKeys(_)) => {
            let (pk, sk) = generate_global_keys(&mut rng);
            eprint!("Public global key: ");
            println!("{}", encode_hex(&pk.encode()));
            eprint!("Secret global key: ");
            println!("{}", encode_hex(&sk.encode()));
        },
        Some(Sub::GenerateEncryptedPseudonym(arg)) => {
            let global_public_key = GroupElement::decode_from_slice(&decode_hex(&arg.args[1]).unwrap()).unwrap();
            let global_encrypted_pseudonym = generate_pseudonym(&arg.args[0], &global_public_key, &mut rng);
            println!("{}", encode_hex(&global_encrypted_pseudonym.encode()));
        },
        Some(Sub::ConvertToLocalPseudonym(arg)) => {
            let global_encrypted_pseudonym = ElGamal::decode(&decode_hex(&arg.args[0]).unwrap()).unwrap();
            let server_secret = &arg.args[1];
            let decryption_context = &arg.args[2];
            let pseudonimisation_context = &arg.args[3];
            let local_encrypted_pseudonym = convert_to_local_pseudonym(&global_encrypted_pseudonym, server_secret, decryption_context, pseudonimisation_context);
            println!("{}", encode_hex(&local_encrypted_pseudonym.encode()));
        },
        Some(Sub::MakeLocalDecryptionKey(arg)) => {
            let global_secret_key = ScalarCanBeZero::decode_from_slice(&decode_hex(&arg.args[0]).unwrap()).unwrap().try_into().expect("global secret key should not be zero");
            let server_secret = &arg.args[1];
            let decryption_context = &arg.args[2];
            let local_decryption_key = make_local_decryption_key(&global_secret_key, server_secret, decryption_context);
            println!("{}", encode_hex(&local_decryption_key.encode()));
        },
        Some(Sub::DecryptLocalPseudonym(arg)) => {
            let encrypted_local_pseudonym = ElGamal::decode(&decode_hex(&arg.args[0]).unwrap()).unwrap();
            let local_decryption_key = ScalarCanBeZero::decode_from_slice(&decode_hex(&arg.args[1]).unwrap()).unwrap().try_into().expect("local decryption key should not be zero");
            let local_pseudonym = decrypt_local_pseudonym(&encrypted_local_pseudonym, &local_decryption_key);
            println!("{}", encode_hex(&local_pseudonym.encode()));
            
        },
        Some(Sub::RerandomizePseudonym(arg)) => {
            let pseudonym = ElGamal::decode(&decode_hex(&arg.args[0]).unwrap()).unwrap();
            let pseudonym = rerandomize(&pseudonym, &ScalarNonZero::random(&mut OsRng));
            println!("{}", encode_hex(&pseudonym.encode()));
        }
        None => todo!(),
    }
}
