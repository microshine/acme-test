
import {config as env} from "dotenv";
env();
import * as assert from "assert";
import fetch from "node-fetch";
import {Convert} from "pvtsutils";
import {AcmeClient, IHeaders} from "../src/client";
import {crypto} from "../src/crypto";
import {AcmeError} from "../src/error";
import {IOrder} from "../src/types";
import {IAuthorization, IHttpChallenge} from "../src/types/authorization";
import {generateCSR} from "./csr";

process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0";

const urlServer = {
  ACME: "https://aeg-dev0-srv.aegdomain2.com/acme/directory",
  test: "http://aeg-dev0-srv.aegdomain2.com/acme-challenge",
  domain: "aeg-dev0-srv.aegdomain2.com",
  LetSEncrypt: "https://acme-staging-v02.api.letsencrypt.org/directory",
  local: "http://localhost:60298/directory",
};
const url = urlServer.LetSEncrypt;

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

    it.only("Error: no agreement to the terms", async () => {
      await assert.rejects(client.createAccount({
        contact: ["mailto:microshine@mail.ru"],
        termsOfServiceAgreed: false,
      }), (err: AcmeError) => {
        assert.equal(!!client.lastNonce, true);
        assert.equal(err.status, 400);
        assert.equal(err.type, "urn:ietf:params:acme:error:malformed");
        return true;
      });
    });

    it.only("Error: find not exist account", async () => {
      await assert.rejects(client.createAccount({
        contact: ["mailto:microshine@mail.ru"],
        onlyReturnExisting: true,
      }), (err: AcmeError) => {
        assert.equal(!!client.lastNonce, true);
        assert.equal(err.status, 400);
        assert.equal(err.type, "urn:ietf:params:acme:error:accountDoesNotExist");
      });
    });

    // todo: mailto
    // todo: validate email

    it("create account", async () => {
      const res = await client.createAccount({
        contact: ["mailto:microshine@mail.ru"],
        termsOfServiceAgreed: true,
      });
      checkHeaders(res);
      checkResAccount(res, 201);
    });

    it("create account with the same key", async () => {
      const res = await client.createAccount({
        contact: ["mailto:microshine2@mail.ru"],
        termsOfServiceAgreed: true,
      });
      checkHeaders(res);
      checkResAccount(res, 200);
    });

    it("finding an account", async () => {
      const res = await client.createAccount({onlyReturnExisting: true});
      checkHeaders(res);
      checkResAccount(res, 200);
    });

    it("account update", async () => {
      const res = await client.updateAccount({contact: ["mailto:testmail@mail.ru"]});
      assert.equal(!!res.link, true);
      assert.equal(!!client.lastNonce, true);
      checkResAccount(res, 200);
    });

    it("account key rollover", async () => {
      const newKey = await crypto.subtle.generateKey(rsaAlg, true, ["sign", "verify"]);
      const res = await client.changeKey(newKey.privateKey);
      assert.equal(!!res.link, true);
      assert.equal(!!client.lastNonce, true);
      checkResAccount(res, 200);
    });

    it("Error: account key rollover", async () => {
      await assert.rejects(client.changeKey(), (err: AcmeError) => {
        // assert.equal(res.headers.has("location"), true);
        assert.equal(!!client.lastNonce, true);
        assert.equal(err.status, 409);
        assert.equal(err.type, "urn:ietf:params:acme:error:incorrectResponse");
      });
    });

    it("deactivate", async () => {
      const res = await client.deactivate();
      assert.equal(!!res.link, true);
      assert.equal(!!client.lastNonce, true);
      assert.equal(res.result.status, "deactivated");
      assert.equal(res.status, 200);
      if (url !== urlServer.LetSEncrypt) {
        assert.equal(!!res.result.orders, true);
      }
    });

  });

  context("Certificate Management", () => {

    let order: IOrder;
    let authorization: IAuthorization;

    // before(async () => {
    //   const acmeKey = process.env.ACME_KEY;
    //   assert.equal(!!acmeKey, true, "Environment variable ACME_KEY does not exist");
    //   authKey = await crypto.subtle.importKey("pkcs8", Buffer.from(acmeKey!, "base64"), rsaAlg, true, ["sign"]);
    // });

    before(async () => {
      const keys = await crypto.subtle.generateKey(rsaAlg, true, ["sign", "verify"]);
      authKey = keys.privateKey;
    });

    before(async () => {
      client = new AcmeClient({authKey});
      await client.initialize(url);
    });

    before(async () => {
      try {
        await client.createAccount({
          onlyReturnExisting: true,
        });
      } catch (error) {
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
      await assert.rejects(
        client.newOrder({
          identifiers: [],
        }), (err: AcmeError) => {
          assert.equal(!!client.lastNonce, true);
          // assert.equal(res.error.type, "urn:ietf:params:acme:error:malformed");
          assert.equal(err.status, 400);
        });
    });

    it("create order", async () => {
      const date = new Date();
      date.setFullYear(date.getFullYear() + 1);
      const params: any = {
        identifiers: [{type: "dns", value: "aeg-dev0-srv.aegdomain2.com"}],
      };
      if (url !== urlServer.LetSEncrypt) {
        params.notAfter = date.toISOString();
        params.notBefore = new Date().toISOString();
      }
      const res = await client.newOrder(params);
      assert.equal(!!res.link, true);
      assert.equal(!!client.lastNonce, true);
      assert.equal(res.status, 201);
      assert.equal(res.result.status, "pending");
      assert.equal(!!res.result.expires, true);
      assert.equal(!!res.result.authorizations, true);
      order = res.result;
    });

    it("authorization", async () => {
      const res = await client.getAuthorization(order.authorizations[0]);
      assert.equal(!!res.link, true);
      // assert.equal(res.headers.has("replay-nonce"), true);
      assert.equal(res.status, 200);
      assert.equal(res.result.status, "pending");
      assert.equal(!!res.result.expires, true);
      assert.equal(!!res.result.identifier, true);
      assert.equal(!!res.result.challenges, true);
      authorization = res.result;
      const challange = authorization.challenges.filter((o) => o.type === "http-01")[0] as IHttpChallenge;
      const account = await client.createAccount({onlyReturnExisting: true});
      // const json = JSON.stringify(account.result.key, Object.keys(account.result.key));
      const json = JSON.stringify(account.result.key, Object.keys(account.result.key).sort());
      await client.createURL(
        urlServer.test, challange.token,
        Convert.ToBase64Url(await crypto.subtle.digest("SHA-256", Buffer.from(json))),
      );
    });

    it("challange http-01 pending", async () => {
      const challange = authorization.challenges.filter((o) => o.type === "http-01")[0] as IHttpChallenge;
      assert.equal(challange.status, "pending");
    });

    it("challange http-01 valid", async () => {
      let challenge = authorization.challenges.filter((o) => o.type === "http-01")[0] as IHttpChallenge;
      await client.getChallenge(challenge.url, "POST");
      let count = 0;
      while (challenge.status === "pending" && count++ < 5) {
        await pause(2000);
        const res = await client.getChallenge(challenge.url, "GET");
        challenge = res.result;
      }
      assert.equal(challenge.status, "valid");
    });

    it("authorization valid", async () => {
      const res = await client.getAuthorization(order.authorizations[0]);
      assert.equal(!!res.link, true);
      // assert.equal(res.headers.has("replay-nonce"), true);
      assert.equal(res.status, 200);
      assert.equal(res.result.status, "valid");
      assert.equal(!!res.result.expires, true);
      assert.equal(!!res.result.identifier, true);
      assert.equal(!!res.result.challenges, true);
      authorization = res.result;
    });

    it("order ready", async () => {
      const params: any = {
        identifiers: [{type: "dns", value: "aeg-dev0-srv.aegdomain2.com"}],
      };
      const res = await client.newOrder(params);
      assert.equal(!!res.link, true);
      assert.equal(!!client.lastNonce, true);
      assert.equal(res.status, 201);
      assert.equal(res.result.status, "ready");
      assert.equal(!!res.result.expires, true);
      assert.equal(!!res.result.authorizations, true);
      order = res.result;
    });

    it("finalize", async () => {
      const csr = await generateCSR(rsaAlg, "aeg-dev0-srv.aegdomain2.com");
      if (!order.finalize) {
        throw new Error("finalize link undefined");
      }
      const res = await client.getFinalize(order.finalize, {csr: Convert.ToBase64Url(csr.csr)});
      checkHeaders(res);
      assert.equal(res.status, 200);
      assert.equal(res.result.status, "valid");
      assert.equal(!!res.result.expires, true);
      assert.equal(!!res.result.authorizations, true);
      assert.equal(!!res.result.certificate, true);
      order = res.result;
    });

    it("certificate", async () => {
      if (!order.certificate) {
        throw new Error("certificate link undefined");
      }
      const res = await fetch(order.certificate, {method: "GET"});
      assert.equal(res.headers.has("link"), true);
      assert.equal(res.status, 200);
      assert.equal(!!(await res.text()), true);
    });

  });

  function checkHeaders(headers: IHeaders) {
    assert.equal(!!headers.link, true);
    assert.equal(!!headers.location, true);
    assert.equal(!!client.lastNonce, true);
  }
  function checkResAccount(res: any, status: number) {
    assert.equal(res.result.status, "valid");
    assert.equal(res.status, status);
    if (url !== urlServer.LetSEncrypt) {
      assert.equal(!!res.result.orders, true);
    }
  }
});

async function pause(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
