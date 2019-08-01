import * as assert from "assert";
import fetch from "node-fetch";
import { Convert } from "pvtsutils";
import { PemConverter } from "webcrypto-core";
import { AcmeClient, RevocationReason } from "../../src/client";
import { crypto } from "../../src/crypto";
import { AcmeError } from "../../src/error";
import { IOrder } from "../../src/types";
import { IAuthorization, IHttpChallenge } from "../../src/types/authorization";
import {
  ALGORITHM, checkHeaders, contextServer, createURL, IDENTIFIER, pause, preparation, URL_SERVER,
} from "../bootstrap";
import { generateCSR } from "../csr";
import { errorType } from "../errors_type";

let authorization: IAuthorization;

contextServer("Certificate Management", () => {

  let order: IOrder;
  let testClient: AcmeClient;

  before(async () => {
    const prep = await preparation(true, true);
    testClient = prep.client;
    if (prep.order) {
      order = prep.order;
    }
  });

  it("Error: Unsupported Media Type", async () => {
    const href = order.authorizations[0];
    const token = await testClient.createJWS("", Object.assign({ url: href }, { kid: testClient.getKeyId() }));
    const res = await fetch(href, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify(token),
    });
    const nonce = res.headers.get("replay-nonce");
    if (nonce) {
      testClient.lastNonce = nonce;
    }
    assert.equal(res.status, 415);
    assert.equal(res.statusText, "Unsupported Media Type");
  });

  it("Error: unsupported algorithm", async () => {
    const newrsaAlg: RsaHashedKeyGenParams = {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-1",
      publicExponent: new Uint8Array([1, 0, 1]),
      modulusLength: 2048,
    };
    const keys = await crypto.subtle.generateKey(newrsaAlg, true, ["sign", "verify"]);
    const newAuthKey = keys.privateKey;
    const newClient = new AcmeClient({ authKey: newAuthKey, debug: !!process.env["ACME_DEBUG"] });
    await newClient.initialize(URL_SERVER);
    await assert.rejects(newClient.createAccount({ termsOfServiceAgreed: true }), (err: AcmeError) => {
      assert.equal(err.status, 400);
      assert.equal(err.type, errorType.badSignatureAlgorithm);
      return true;
    });
  });

  it.skip("Error: bad public key", async () => {
    const newrsaAlg: RsaHashedKeyGenParams = {
      name: "RSASSA-PKCS1-v1_5",
      hash: "p-384",
      publicExponent: new Uint8Array([1, 0, 1]),
      modulusLength: 2048,
    };
    const keys = await crypto.subtle.generateKey(newrsaAlg, true, ["sign", "verify"]);
    const newAuthKey = keys.privateKey;
    const newClient = new AcmeClient({ authKey: newAuthKey, debug: !!process.env["ACME_DEBUG"] });
    await newClient.initialize(URL_SERVER);
    await assert.rejects(newClient.createAccount({ termsOfServiceAgreed: true }), (err: AcmeError) => {
      assert.equal(err.status, 400);
      assert.equal(err.type, errorType.badPublicKey);
      return true;
    });
  });

  it("authorization", async () => {
    const res = await testClient.getAuthorization(order.authorizations[0]);
    assert.equal(!!res.link, true);
    // assert.equal(res.headers.has("replay-nonce"), true);
    assert.equal(res.status, 200);
    assert.equal(res.result.status, "pending");
    assert.equal(!!res.result.expires, true);
    assert.equal(!!res.result.identifier, true);
    assert.equal(!!res.result.challenges, true);
    authorization = res.result;
  });

  it("challange http-01 pending", async () => {
    const challange = authorization.challenges.filter((o) => o.type === "http-01")[0] as IHttpChallenge;
    assert.equal(challange.status, "pending");
  });

  it("challange http-01 valid", async () => {
    await createURL(testClient, authorization);
    let challenge = authorization.challenges.filter((o) => o.type === "http-01")[0] as IHttpChallenge;
    await testClient.getChallenge(challenge.url, "POST");
    let count = 0;
    while (challenge.status === "pending" && count++ < 5) {
      await pause(2000);
      const res = await testClient.getChallenge(challenge.url, "GET");
      challenge = res.result;
    }
    assert.equal(challenge.status, "valid");
  });

  it("authorization valid", async () => {
    const res = await testClient.getAuthorization(order.authorizations[0]);
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
    const params: any = { identifiers: [IDENTIFIER] };
    const res = await testClient.newOrder(params);
    assert.equal(!!res.link, true);
    assert.equal(!!testClient.lastNonce, true);
    assert.equal(res.status, 201);
    assert.equal(res.result.status, "ready");
    assert.equal(!!res.result.expires, true);
    assert.equal(!!res.result.authorizations, true);
    order = res.result;
  });

  it("Error: finalize with bad CSR without identifier", async () => {
    const csr = await generateCSR(ALGORITHM);
    if (!order.finalize) {
      throw new Error("finalize link undefined");
    }
    await assert.rejects(
      testClient.finalize(order.finalize, { csr: Convert.ToBase64Url(csr.csr) }), (err: AcmeError) => {
        assert.equal(err.status, 400);
        assert.equal(err.type, errorType.malformed);
        return true;
      });
  });

  it("Error: finalize with CSR with bad identifier", async () => {
    const csr = await generateCSR(ALGORITHM, "badIdentifier.com");
    if (!order.finalize) {
      throw new Error("finalize link undefined");
    }
    await assert.rejects(
      testClient.finalize(order.finalize, { csr: Convert.ToBase64Url(csr.csr) }), (err: AcmeError) => {
        assert.equal(err.status, 403);
        assert.equal(err.type, errorType.unauthorized);
        return true;
      });
  });

  it("finalize", async () => {
    const csr = await generateCSR(ALGORITHM, IDENTIFIER.value);
    if (!order.finalize) {
      throw new Error("finalize link undefined");
    }
    const res = await testClient.finalize(order.finalize, { csr: Convert.ToBase64Url(csr.csr) });
    checkHeaders(testClient, res);
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
    const res = await testClient.getCertificate(order.certificate);
    assert.equal(!!res.link, true);
    assert.equal(res.status, 200);
    assert.equal(!!res.result, true);
  });

  it("Error: bad revocation reason", async () => {
    if (!order.certificate) {
      throw new Error("certificate link undefined");
    }
    const res = await testClient.getCertificate(order.certificate);
    const cert = PemConverter.toUint8Array(res.result[0]);
    await assert.rejects(testClient.revoke(cert, 15), (err: AcmeError) => {
      assert.equal(err.status, 400);
      assert.equal(err.type, errorType.badRevocationReason);
      return true;
    });
  });

  it("revoke", async () => {
    if (!order.certificate) {
      throw new Error("certificate link undefined");
    }
    const res = await testClient.getCertificate(order.certificate);
    const cert = PemConverter.toUint8Array(res.result[0]);
    const revoke = await testClient.revoke(cert, RevocationReason.Unspecified);
    assert.equal(revoke.status, 200);
    assert.equal(!!revoke.link, true);
  });

  it("revoke without reason", async () => {
    const prep = await preparation(true, true);
    testClient = prep.client;
    if (prep.order) {
      order = prep.order;
    }
    authorization = (await testClient.getAuthorization(order.authorizations[0])).result;
    await createURL(testClient, authorization);
    const challenge = authorization.challenges.filter((o) => o.type === "http-01")[0] as IHttpChallenge;
    await testClient.getChallenge(challenge.url, "POST");
    await pause(4000);
    const csr = await generateCSR(ALGORITHM, IDENTIFIER.value);
    order = (await testClient.finalize(order.finalize, { csr: Convert.ToBase64Url(csr.csr) })).result;
    if (!order.certificate) {
      throw new Error("certificate link undefined");
    }
    const res = await testClient.getCertificate(order.certificate);
    const cert = PemConverter.toUint8Array(res.result[0]);
    const revoke = await testClient.revoke(cert);
    assert.equal(revoke.status, 200);
    assert.equal(!!revoke.link, true);
  });

  it("Error: already revoked", async () => {
    if (!order.certificate) {
      throw new Error("certificate link undefined");
    }
    const res = await testClient.getCertificate(order.certificate);
    const cert = PemConverter.toUint8Array(res.result[0]);
    await assert.rejects(
      testClient.revoke(cert, RevocationReason.Unspecified), (err: AcmeError) => {
        assert.equal(err.status, 400);
        assert.equal(err.type, errorType.alreadyRevoked);
        return true;
      });
  });

  it("Error: access denied", async () => {
    const prep = await preparation(true, true);
    testClient = prep.client;
    await assert.rejects(testClient.getAuthorization(order.authorizations[0]), (err: AcmeError) => {
      assert.equal(err.status, 400);
      assert.equal(err.type, errorType.malformed);
      return true;
    });
  });
});
