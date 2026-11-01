// Build step zero: JS client <-> Rust server OPAQUE round trip.
// Proves (1) the wire formats agree, (2) export_key is stable across logins,
// (3) the server is KSF-agnostic, so password and PIN can stretch differently.
import * as opaque from "@serenity-kit/opaque";
import { execFileSync } from "node:child_process";
import assert from "node:assert/strict";

type Ksf = opaque.client.FinishRegistrationParams["keyStretching"];

const rust = (...args: string[]) =>
  execFileSync(
    "cargo",
    ["run", "-q", "-p", "sahichap-server", "--bin", "opaque-spike", "--", ...args],
    { encoding: "utf8" },
  ).trim();

function roundTrip(label: string, password: string, keyStretching: Ksf) {
  const user = "alice@example.com";
  const serverSetup = rust("setup");

  // Registration
  const reg = opaque.client.startRegistration({ password });
  const registrationResponse = rust("register-start", serverSetup, user, reg.registrationRequest);
  const regDone = opaque.client.finishRegistration({
    clientRegistrationState: reg.clientRegistrationState,
    registrationResponse,
    password,
    keyStretching,
  });
  const record = rust("register-finish", regDone.registrationRecord);

  // Login with the right credential
  const login = opaque.client.startLogin({ password });
  const [loginResponse, serverLoginState] = rust(
    "login-start", serverSetup, user, record, login.startLoginRequest,
  ).split("\n");
  const loginDone = opaque.client.finishLogin({
    clientLoginState: login.clientLoginState,
    loginResponse,
    password,
    keyStretching,
  });
  assert.ok(loginDone, `${label}: client rejected a correct credential`);
  const serverSessionKey = rust("login-finish", serverLoginState, loginDone.finishLoginRequest);

  assert.equal(serverSessionKey, loginDone.sessionKey, `${label}: session keys differ`);
  assert.equal(loginDone.exportKey, regDone.exportKey, `${label}: export_key not stable`);

  // Login with the wrong credential: client detects it after KE2, server never hears KE3.
  const bad = opaque.client.startLogin({ password: password + "x" });
  const [badResponse] = rust("login-start", serverSetup, user, record, bad.startLoginRequest).split("\n");
  const badDone = opaque.client.finishLogin({
    clientLoginState: bad.clientLoginState,
    loginResponse: badResponse,
    password: password + "x",
    keyStretching,
  });
  assert.equal(badDone, undefined, `${label}: wrong credential was accepted`);

  console.log(`ok  ${label}`);
}

await opaque.ready;
roundTrip("password / memory-constrained argon2id", "correct horse battery staple", "memory-constrained");
roundTrip("pin / minimal argon2id", "123456", { "argon2id-custom": { memory: 8, iterations: 1, parallelism: 1 } });
