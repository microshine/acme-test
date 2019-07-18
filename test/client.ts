
import {config as env} from "dotenv";
env();
import * as assert from "assert";
import {Convert} from "pvtsutils";
import {AcmeClient, IHeaders} from "../src/client";
import {crypto} from "../src/crypto";
import {AcmeError} from "../src/error";
import {IOrder} from "../src/types";
import {IAuthorization, IHttpChallenge} from "../src/types/authorization";
import {generateCSR} from "./csr";

process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0";

export const urlServer = {
  test: "http://aeg-dev0-srv.aegdomain2.com/acme-challenge",
};

const url = process.env["URL_SERVER"] || "";
const domain = domainFromURL(url);
let authKey: CryptoKey;
let client: AcmeClient;
let order: IOrder;
let authorization: IAuthorization;
const rsaAlg: RsaHashedKeyGenParams = {
  name: "RSASSA-PKCS1-v1_5",
  hash: "SHA-256",
  publicExponent: new Uint8Array([1, 0, 1]),
  modulusLength: 2048,
};
const identifier = {type: "dns", value: "aeg-dev0-srv.aegdomain2.com"};

context(`Client ${url}`, () => {

  context("Directory", () => {

    before(async () => {
      await preparation();
    });

    it("directory", async () => {
      if (client.directory) {
        assert.equal(!!client.directory.keyChange, true);
        assert.equal(!!client.directory.newAccount, true);
        assert.equal(!!client.directory.newNonce, true);
        assert.equal(!!client.directory.newOrder, true);
        assert.equal(!!client.directory.revokeCert, true);
        return true;
      }
    });

    it("Error: replay-nonce", async () => {
      await preparation(true);
      client.lastNonce = "badNonce";
      const params: any = {identifiers: [identifier]};
      await assert.rejects(client.newOrder(params), (err: AcmeError) => {
        assert.equal(err.status, 400);
        assert.equal(err.type, "urn:ietf:params:acme:error:badNonce");
        return true;
      });
    });

    it("Error: method not allowed", async () => {
      await assert.rejects(client.request(`${url}/ooops`), (err: AcmeError) => {
        assert.equal(err.status, 405);
        assert.equal(err.type, "urn:ietf:params:acme:error:malformed");
        return true;
      });
    });

  });

  context("Account Management", () => {

    before(async () => {
      await preparation();
    });

    it("Error: no agreement to the terms", async () => {
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

    it("Error: find not exist account", async () => {
      await assert.rejects(client.createAccount({
        contact: ["mailto:microshine@mail.ru"],
        onlyReturnExisting: true,
      }), (err: AcmeError) => {
        assert.equal(!!client.lastNonce, true);
        assert.equal(err.status, 400);
        assert.equal(err.type, "urn:ietf:params:acme:error:accountDoesNotExist");
        return true;
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

    it("update account", async () => {
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
        return true;
      });
    });

    it("Error: method not allowed for GET", async () => {
      const res = await client.createAccount({
        contact: ["mailto:microshine@mail.ru"],
        onlyReturnExisting: true,
      });
      if (res.location) {
        await assert.rejects(client.request(res.location, "GET"), (err: AcmeError) => {
          assert.equal(err.status, 405);
          assert.equal(err.type, "urn:ietf:params:acme:error:malformed");
          return true;
        });
      }
    });

    it("deactivate account", async () => {
      const res = await client.deactivateAccount();
      assert.equal(!!res.link, true);
      assert.equal(!!client.lastNonce, true);
      assert.equal(res.result.status, "deactivated");
      assert.equal(res.status, 200);
    });

    it("Error: account with the provided public key exists but is deactivated", async () => {
      await assert.rejects(client.createAccount({
        contact: ["mailto:microshine@mail.ru"],
        termsOfServiceAgreed: true,
      }), (err: AcmeError) => {
        assert.equal(!!client.lastNonce, true);
        assert.equal(err.status, 401);
        assert.equal(err.type, "urn:ietf:params:acme:error:unauthorized");
        return true;
      });
    });

  });

  context("Order Management", () => {

    before(async () => {
      await preparation(true);
    });

    it("Error: create order without required params", async () => {
      const date = new Date();
      date.setFullYear(date.getFullYear() + 1);
      await assert.rejects(
        client.newOrder({identifiers: []}), (err: AcmeError) => {
          assert.equal(!!client.lastNonce, true);
          assert.equal(err.type, "urn:ietf:params:acme:error:malformed");
          assert.equal(err.status, 400);
          return true;
        });
    });

    it("create order", async () => {
      const date = new Date();
      date.setFullYear(date.getFullYear() + 1);
      const params: any = {identifiers: [identifier]};
      const res = await client.newOrder(params);
      assert.equal(!!res.link, true);
      assert.equal(!!client.lastNonce, true);
      assert.equal(res.status, 201);
      assert.equal(res.result.status, "pending");
      assert.equal(!!res.result.expires, true);
      assert.equal(!!res.result.authorizations, true);
      order = res.result;
    });

    it("create duplicate order", async () => {
      const params: any = {identifiers: [identifier]};
      const order1 = await client.newOrder(params);
      const order2 = await client.newOrder(params);
      assert.equal(order2.location, order1.location);
      assert.deepEqual(order1.result.authorizations.sort(), order2.result.authorizations.sort());
      assert.equal(order2.status, 201);
    });

    it("create new order with extended identifier", async () => {
      const params1: any = {
        identifiers: [
          {type: "dns", value: "test5.com"},
        ],
      };
      const order1 = await client.newOrder(params1);
      const params2: any = {
        identifiers: [
          {type: "dns", value: "test5.com"},
          {type: "dns", value: "test6.com"},
        ],
      };
      const order2 = await client.newOrder(params2);
      assert.notEqual(order1.location, order2.location);
      assert.equal(order1.result.authorizations[0], order2.result.authorizations.sort()[0]);
      assert.equal(order2.status, 201);
    });

    it("create new order with one of the  identifier", async () => {
      const params1: any = {
        identifiers: [
          {type: "dns", value: "test3.com"},
          {type: "dns", value: "test4.com"},
        ],
      };
      const order1 = await client.newOrder(params1);
      const params2: any = {
        identifiers: [
          {type: "dns", value: "test3.com"},
        ],
      };
      const order2 = await client.newOrder(params2);
      assert.notEqual(order1.location, order2.location);
      assert.deepEqual(order1.result.authorizations.sort()[0], order2.result.authorizations[0]);
      assert.equal(order2.status, 201);
    });

    it("create new order with same identifiers", async () => {
      const params1: any = {
        identifiers: [
          {type: "dns", value: "test1.com"},
          {type: "dns", value: "test2.com"},
        ],
      };
      const order1 = await client.newOrder(params1);
      const params2: any = {
        identifiers: [
          {type: "dns", value: "test2.com"},
          {type: "dns", value: "test1.com"},
        ],
      };
      const order2 = await client.newOrder(params2);
      assert.equal(order1.location, order2.location);
      assert.deepEqual(order1.result.authorizations.sort(), order2.result.authorizations.sort());
      assert.equal(order2.status, 201);
    });

    it("Error: Account is not valid, has status deactivated", async () => {
      await client.deactivateAccount();
      const params: any = {identifiers: [identifier]};
      await assert.rejects(client.newOrder(params), (err: AcmeError) => {
        assert.equal(!!client.lastNonce, true);
        assert.equal(err.status, 401);
        assert.equal(err.type, "urn:ietf:params:acme:error:unauthorized");
        return true;
      });
    });

  });

  context("Certificate Management", () => {

    before(async () => {
      await preparation(true, true);
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
      delete account.result.key.alg;
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
        const res = await client.getChallenge(challenge.url, "POST");
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
      const params: any = {identifiers: [identifier]};
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
      const csr = await generateCSR(rsaAlg, domain);
      if (!order.finalize) {
        throw new Error("finalize link undefined");
      }
      const res = await client.finalize(order.finalize, {csr: Convert.ToBase64Url(csr.csr)});
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
      const res = await client.getCertificate(order.certificate);
      assert.equal(!!res.link, true);
      assert.equal(res.status, 200);
      assert.equal(!!res.result, true);
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
  }
});

async function pause(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Получение домена из URL
 * @param url 
 */
function domainFromURL(url: string) {
  const regex = /(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]/gm;
  const matches = regex.exec(url);
  if (!matches) {
    throw new Error("Not parse domain from url");
  }
  return matches[1];
}

async function preparation(newAccount?: boolean, newOrder?: boolean) {
  // const acmeKey = process.env.ACME_KEY;
  // assert.equal(!!acmeKey, true, "Environment variable ACME_KEY does not exist");
  // authKey = await crypto.subtle.importKey("pkcs8", Buffer.from(acmeKey!, "base64"), rsaAlg, true, ["sign"]);

  const keys = await crypto.subtle.generateKey(rsaAlg, true, ["sign", "verify"]);
  authKey = keys.privateKey;
  client = new AcmeClient({authKey, debug: !!process.env["ACME_DEBUG"]});
  await client.initialize(url);

  if (newAccount) {
    await client.createAccount({
      contact: ["mailto:microshine@mail.ru"],
      termsOfServiceAgreed: true,
    });
  }

  if (newOrder) {
    const params: any = {identifiers: [identifier]};
    const res = await client.newOrder(params);
    order = res.result;
  }
}
