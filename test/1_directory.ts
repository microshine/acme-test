import * as assert from "assert";
import { AcmeError } from "../src/error";
import { IDENTIFIER, preparation, testClient, URL_SERVER } from "./bootstrap";

context("Directory", () => {

  before(async () => {
    await preparation();
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

  it("Error: replay-nonce", async () => {
    await preparation(true);
    testClient.lastNonce = "badNonce";
    const params: any = { identifiers: [IDENTIFIER] };
    await assert.rejects(testClient.newOrder(params), (err: AcmeError) => {
      assert.equal(err.status, 400);
      assert.equal(err.type, "urn:ietf:params:acme:error:badNonce");
      return true;
    });
  });

  it("Error: method not allowed", async () => {
    await assert.rejects(testClient.request(`${URL_SERVER}/ooops`), (err: AcmeError) => {
      assert.equal(err.status, 405);
      assert.equal(err.type, "urn:ietf:params:acme:error:malformed");
      return true;
    });
  });

});
