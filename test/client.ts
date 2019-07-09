import * as assert from "assert";
import { crypto } from "../src/crypto";
import { AcmeClient } from "../src/client";

context("Client", () => {

  let client: AcmeClient;
  let authKey: CryptoKey;
  const rsaAlg: RsaHashedKeyGenParams = {
    name: "RSASSA-PKCS1-v1_5",
    hash: "SHA-256",
    publicExponent: new Uint8Array([1, 0, 1]),
    modulusLength: 2048,
  };
  const url = "http://localhost:60298/directory";

  before(async () => {
    const keys = await crypto.subtle.generateKey(rsaAlg, true, ["sign", "verify"]);
    authKey = keys.privateKey;
    client = new AcmeClient({ authKey });
    await client.initialize(url);
  });

  it("create account termsOfServiceAgreed:false", async () => {
    const account = await client.createAccount({
      contact: ["mailto:microshine@mail.ru"],
      onlyReturnExisting: false,
      termsOfServiceAgreed: false,
    });
    assert.equal(!!account, true);
  });

  it("find account which doesn't exist", async () => {
    const account = await client.findAccount();
    assert.equal(!!account, false);
  });

  it("create account", async () => {
    const account = await client.createAccount({
      contact: ["mailto:microshine@mail.ru"],
      onlyReturnExisting: false,
      termsOfServiceAgreed: true,
    });
    assert.equal(!!account, true);
  });

  it("create account with the same key", async () => {
    const account = await client.createAccount({
      contact: ["mailto:microshine2@mail.ru"],
      onlyReturnExisting: false,
      termsOfServiceAgreed: true,
    });
    assert.equal(!!account, true);
  });

  it("find account which exist", async () => {
    const account = await client.findAccount();
    assert.equal(!!account, true);
  });

  it("update account", async () => {
    const account = await client.updateAccount({contact: ["mailto:testmail@mail.ru"]});
    assert.equal(!!account, true);
  });

});
