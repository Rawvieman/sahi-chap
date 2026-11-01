//! Build step zero: the server half of OPAQUE as a stateless CLI, driven by
//! packages/sdk/src/opaque-spike.ts. Every argument and output is base64url
//! (no padding), the encoding @serenity-kit/opaque uses on the wire.
//!
//!   setup                                   -> server_setup
//!   register-start  <setup> <user> <req>    -> registration_response
//!   register-finish <upload>                -> record
//!   login-start     <setup> <user> <record> <ke1> -> ke2 "\n" login_state
//!   login-finish    <login_state> <ke3>     -> session_key

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use opaque_ke::{
    CipherSuite, CredentialFinalization, CredentialRequest, RegistrationRequest,
    RegistrationUpload, ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;
use std::error::Error;

/// Must match the suite @serenity-kit/opaque is compiled with.
/// Ksf is only ever run by the client, so the server's choice here never
/// touches the wire; the client picks Argon2 parameters per credential.
struct Suite;
impl CipherSuite for Suite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = opaque_ke::ksf::Identity;
}

fn b64(s: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(B64.decode(s)?)
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("");

    let out: Vec<u8> = match (cmd, &args[1..]) {
        ("setup", []) => ServerSetup::<Suite>::new(&mut OsRng).serialize().to_vec(),

        ("register-start", [setup, user, req]) => {
            let setup = ServerSetup::<Suite>::deserialize(&b64(setup)?)?;
            let req = RegistrationRequest::<Suite>::deserialize(&b64(req)?)?;
            ServerRegistration::start(&setup, req, user.as_bytes())?
                .message
                .serialize()
                .to_vec()
        }

        ("register-finish", [upload]) => {
            let upload = RegistrationUpload::<Suite>::deserialize(&b64(upload)?)?;
            ServerRegistration::finish(upload).serialize().to_vec()
        }

        ("login-start", [setup, user, record, ke1]) => {
            let setup = ServerSetup::<Suite>::deserialize(&b64(setup)?)?;
            let record = ServerRegistration::<Suite>::deserialize(&b64(record)?)?;
            let ke1 = CredentialRequest::<Suite>::deserialize(&b64(ke1)?)?;
            let r = ServerLogin::start(
                &mut OsRng,
                &setup,
                Some(record),
                ke1,
                user.as_bytes(),
                ServerLoginParameters::default(),
            )?;
            println!("{}", B64.encode(r.message.serialize()));
            r.state.serialize().to_vec()
        }

        ("login-finish", [state, ke3]) => {
            let state = ServerLogin::<Suite>::deserialize(&b64(state)?)?;
            let ke3 = CredentialFinalization::<Suite>::deserialize(&b64(ke3)?)?;
            state
                .finish(ke3, ServerLoginParameters::default())?
                .session_key
                .to_vec()
        }

        _ => return Err(format!("bad usage: {}", args.join(" ")).into()),
    };

    println!("{}", B64.encode(out));
    Ok(())
}
