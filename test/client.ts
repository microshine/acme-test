import {config as env} from "dotenv";
env();
import * as assert from "assert";
import {Headers} from "node-fetch";
import fetch from "node-fetch";
import {AcmeClient} from "../src/client";
import {crypto} from "../src/crypto";

const urlServer = {
  LetSEncrypt: "https://acme-staging-v02.api.letsencrypt.org/directory",
  local: "http://localhost:60298/directory",
};
const url = urlServer.local;

context(`Client ${url}`, () => {

  let client: AcmeClient;
  let authKey: CryptoKey;
  const rsaAlg: RsaHashedKeyGenParams = {
    name: "RSASSA-PKCS1-v1_5",
    hash: "SHA-256",
    publicExponent: new Uint8Array([1, 0, 1]),
    modulusLength: 2048,
  };

  context("Directory", () => {

    it("directory", async () => {
      const res = await fetch(url, {method: "GET"});
      const body = await res.json();
      assert.equal(!!body.keyChange, true);
      assert.equal(!!body.newAccount, true);
      assert.equal(!!body.newNonce, true);
      assert.equal(!!body.newOrder, true);
      assert.equal(!!body.revokeCert, true);
    });
  });

  context("Account Management", () => {

    before(async () => {
      const keys = await crypto.subtle.generateKey(rsaAlg, true, ["sign", "verify"]);
      authKey = keys.privateKey;
    });

    before(async () => {
      client = new AcmeClient({authKey});
      await client.initialize(url);
    });

    it("Error: no agreement to the terms", async () => {
      const res = await client.createAccount({
        contact: ["mailto:microshine@mail.ru"],
        termsOfServiceAgreed: false,
      });
      if (!res.error) {
        throw new Error("No Error");
      }
      assert.equal(res.headers.has("replay-nonce"), true);
      assert.equal(res.error.status, 400);
      assert.equal(res.status, 400);
      assert.equal(res.error.type, "urn:ietf:params:acme:error:malformed");
    });

    it("Error: find not exist account", async () => {
      const res = await client.createAccount({
        contact: ["mailto:microshine@mail.ru"],
        onlyReturnExisting: true,
      });
      if (!res.error) {
        throw new Error("No Error");
      }
      assert.equal(res.headers.has("replay-nonce"), true);
      assert.equal(res.error.status, 400);
      assert.equal(res.status, 400);
      assert.equal(res.error.type, "urn:ietf:params:acme:error:accountDoesNotExist");
    });

    // mailto
    // validate email

    it("create account", async () => {
      const res = await client.createAccount({
        contact: ["mailto:microshine@mail.ru"],
        termsOfServiceAgreed: true,
      });
      checkHeaders(res.headers);
      checkResAccount(res, 201);
    });

    it("create account with the same key", async () => {
      const res = await client.createAccount({
        contact: ["mailto:microshine2@mail.ru"],
        termsOfServiceAgreed: true,
      });
      checkHeaders(res.headers);
      checkResAccount(res, 200);
    });

    it("finding an account", async () => {
      const res = await client.createAccount({onlyReturnExisting: true});
      checkHeaders(res.headers);
      checkResAccount(res, 200);
    });

    it("account update", async () => {
      const res = await client.updateAccount({contact: ["mailto:testmail@mail.ru"]});
      assert.equal(res.headers.has("link"), true);
      assert.equal(res.headers.has("replay-nonce"), true);
      assert.equal(res.result.status, "valid");
      assert.equal(res.status, 200);
      if (url !== urlServer.LetSEncrypt) {
        assert.equal(!!res.result.orders, true);
      }
    });

    it("account key rollover", async () => {
      const newKey = await crypto.subtle.generateKey(rsaAlg, true, ["sign", "verify"]);
      const res = await client.changeKey(newKey.privateKey);
      assert.equal(res.headers.has("link"), true);
      assert.equal(res.headers.has("replay-nonce"), true);
      checkResAccount(res, 200);
    });

    it("Error: account key rollover", async () => {
      const res = await client.changeKey();
      if (!res.error) {
        throw new Error("No Error");
      }
      assert.equal(res.headers.has("location"), true);
      assert.equal(res.headers.has("replay-nonce"), true);
      assert.equal(res.status, 409);
      assert.equal(res.error.status, 409);
      assert.equal(res.error.type, "urn:ietf:params:acme:error:incorrectResponse");
    });

    it("deactivate", async () => {
      const res = await client.deactivate();
      assert.equal(res.headers.has("link"), true);
      assert.equal(res.headers.has("replay-nonce"), true);
      assert.equal(res.result.status, "deactivated");
      assert.equal(res.status, 200);
      if (url !== urlServer.LetSEncrypt) {
        assert.equal(!!res.result.orders, true);
      }
    });

  });

  context("Certificate Management", () => {

    before(async () => {
      const acmeKey = process.env.ACME_KEY;
      assert.equal(!!acmeKey, true, "Environment variable ACME_KEY does not exist");
      authKey = await crypto.subtle.importKey("pkcs8", Buffer.from(acmeKey!, "base64"), rsaAlg, true, ["sign"]);
    });

    before(async () => {
      client = new AcmeClient({authKey});
      await client.initialize(url);
    });

    before(async () => {
      const res = await client.createAccount({
        onlyReturnExisting: true,
      });
      if (res.error) {
        // create new account
        await client.createAccount({
          contact: ["mailto:microshine@mail.ru"],
          termsOfServiceAgreed: true,
        });
      }
    });

    it("Error: create order without required params", async () => {
      const date = new Date();
      date.setFullYear(date.getFullYear() + 1);
      const res = await client.newOrder({
        identifiers: [],
      });
      if (!res.error) {
        throw new Error("No Error");
      }
      assert.equal(res.headers.has("replay-nonce"), true);
      assert.equal(res.error.type, "urn:ietf:params:acme:error:malformed");
      assert.equal(res.status, 400);
      assert.equal(res.error.status, 400);
    });

    it("create order", async () => {
      const date = new Date();
      date.setFullYear(date.getFullYear() + 1);
      const params: any = {
        identifiers: [
          {type: "dns", value: "www.example.org"},
          {type: "dns", value: "example.org"},
        ],
      };
      if (url !== urlServer.LetSEncrypt) {
        params.notAfter = date.toISOString();
        params.notBefore = new Date().toISOString();
      }
      const res = await client.newOrder(params);
      assert.equal(res.headers.has("link"), true);
      assert.equal(res.headers.has("replay-nonce"), true);
      assert.equal(res.status, 201);
      assert.equal(res.result.status, "pending");
      assert.equal(!!res.result.expires, true);
      assert.equal(!!res.result.authorizations, true);
    });

  });

  function checkHeaders(headers: Headers) {
    assert.equal(headers.has("link"), true);
    assert.equal(headers.has("location"), true);
    assert.equal(headers.has("replay-nonce"), true);
  }
  function checkResAccount(res: any, status: number) {
    assert.equal(res.result.status, "valid");
    assert.equal(res.status, status);
    if (url !== urlServer.LetSEncrypt) {
      assert.equal(!!res.result.orders, true);
    }
  }
});
