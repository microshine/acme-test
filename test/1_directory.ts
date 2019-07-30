import * as assert from "assert";
import { AcmeClient } from "../src/client";
import { AcmeError } from "../src/error";
import { IDENTIFIER, preparation, URL_SERVER } from "./bootstrap";
import { errorType } from "./errors_type";

context("Directory", () => {

  let testClient: AcmeClient;

  before(async () => {
    const prep = await preparation();
    testClient = prep.client;
  });

  it("directory", async () => {
    if (testClient.directory) {
      assert.equal(!!testClient.directory.keyChange, true);
      assert.equal(!!testClient.directory.newAccount, true);
      assert.equal(!!testClient.directory.newNonce, true);
      assert.equal(!!testClient.directory.newOrder, true);
      assert.equal(!!testClient.directory.revokeCert, true);
      return true;
    }
  });

  it.only("Error: replay-nonce", async () => {
    const prep = await preparation(true);
    testClient = prep.client;
    testClient.lastNonce = "badNonce";
    const params: any = { identifiers: [IDENTIFIER] };
    await assert.rejects(testClient.newOrder(params), (err: AcmeError) => {
      assert.equal(err.status, 400);
      assert.equal(err.type, errorType.badNonce);
      return true;
    });
  });

  it("Error: method not allowed", async () => {
    await assert.rejects(testClient.request(`${URL_SERVER}/ooops`), (err: AcmeError) => {
      assert.equal(err.status, 405);
      assert.equal(err.type, errorType.malformed);
      return true;
    });
  });

});
