import * as assert from "assert";
import fetch from "node-fetch";
import { AcmeClient } from "../src/client";
import { crypto } from "../src/crypto";
import { AcmeError } from "../src/error";
import { ALGORITHM, checkHeaders, checkResAccount, preparation } from "./bootstrap";
import { errorType } from "./errors_type";

context("Account Management", () => {

  let testClient: AcmeClient;

  before(async () => {
    const prep = await preparation();
    testClient = prep.client;
  });

  it("Error: no agreement to the terms", async () => {
    await assert.rejects(testClient.createAccount({
      contact: ["mailto:microshine@mail.ru"],
      termsOfServiceAgreed: false,
    }), (err: AcmeError) => {
      assert.equal(!!testClient.lastNonce, true);
      assert.equal(err.status, 400);
      assert.equal(err.type, errorType.malformed);
      return true;
    });
  });

  it("Error: find not exist account", async () => {
    await assert.rejects(testClient.createAccount({
      contact: ["mailto:microshine@mail.ru"],
      onlyReturnExisting: true,
    }), (err: AcmeError) => {
      assert.equal(!!testClient.lastNonce, true);
      assert.equal(err.status, 400);
      assert.equal(err.type, errorType.accountDoesNotExist);
      return true;
    });
  });

  it("Error: create account with unsupported contact", async () => {
    await assert.rejects(testClient.createAccount({
      contact: ["mailt:microshine@mail.ru"],
      termsOfServiceAgreed: true,
    }), (err: AcmeError) => {
      assert.equal(err.status, 400);
      assert.equal(err.type, errorType.unsupportedContact);
      return true;
    });
  });

  it("Error: create account with invalid contact", async () => {
    await assert.rejects(testClient.createAccount({
      contact: ["mailto:microshine"],
      termsOfServiceAgreed: true,
    }), (err: AcmeError) => {
      assert.equal(err.status, 400);
      assert.equal(err.type, errorType.invalidContact);
      return true;
    });
  });
  // todo: mailto
  // todo: validate email
  it("create account", async () => {
    const res = await testClient.createAccount({
      contact: ["mailto:microshine@mail.ru"],
      termsOfServiceAgreed: true,
    });
    checkHeaders(testClient, res);
    checkResAccount(res, 201);
  });

  it("create account with the same key", async () => {
    const res = await testClient.createAccount({
      contact: ["mailto:microshine2@mail.ru"],
      termsOfServiceAgreed: true,
    });
    checkHeaders(testClient, res);
    checkResAccount(res, 200);
  });

  it("finding an account", async () => {
    const res = await testClient.createAccount({ onlyReturnExisting: true });
    checkHeaders(testClient, res);
    checkResAccount(res, 200);
  });

  it("update account", async () => {
    const res = await testClient.updateAccount({ contact: ["mailto:testmail@mail.ru"] });
    assert.equal(!!res.link, true);
    assert.equal(!!testClient.lastNonce, true);
    checkResAccount(res, 200);
  });

  it("account key rollover", async () => {
    const newKey = await crypto.subtle.generateKey(ALGORITHM, true, ["sign", "verify"]);
    const res = await testClient.changeKey(newKey.privateKey);
    assert.equal(!!res.link, true);
    assert.equal(!!testClient.lastNonce, true);
    checkResAccount(res, 200);
  });

  it("Error: account key rollover", async () => {
    await assert.rejects(testClient.changeKey(), (err: AcmeError) => {
      // assert.equal(res.headers.has("location"), true);
      assert.equal(!!testClient.lastNonce, true);
      assert.equal(err.status, 409);
      assert.equal(err.type, errorType.incorrectResponse);
      return true;
    });
  });

  it("Error: method not allowed for GET", async () => {
    const res = await testClient.createAccount({
      contact: ["mailto:microshine@mail.ru"],
      onlyReturnExisting: true,
    });
    if (res.location) {
      await assert.rejects(fetch(res.location, { method: "GET" }), (err: any) => {
        assert.equal(err.status, 405);
        assert.equal(err.type, errorType.malformed);
        return true;
      });
    }
  });

  it("deactivate account", async () => {
    const res = await testClient.deactivateAccount();
    assert.equal(!!res.link, true);
    assert.equal(!!testClient.lastNonce, true);
    assert.equal(res.result.status, "deactivated");
    assert.equal(res.status, 200);
  });

  it("Error: account with the provided public key exists but is deactivated", async () => {
    await assert.rejects(testClient.createAccount({
      contact: ["mailto:microshine@mail.ru"],
      termsOfServiceAgreed: true,
    }), (err: AcmeError) => {
      assert.equal(!!testClient.lastNonce, true);
      assert.equal(err.status, 401);
      assert.equal(err.type, errorType.unauthorized);
      return true;
    });
  });

});
