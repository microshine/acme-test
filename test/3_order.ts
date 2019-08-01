import * as assert from "assert";
import { AcmeClient } from "../src/client";
import { AcmeError } from "../src/error";
import { IDENTIFIER, itServer, preparation } from "./bootstrap";
import { errorType } from "./errors_type";

context("Order Management", () => {

  let testClient: AcmeClient;

  before(async () => {
    const prep = await preparation(true);
    testClient = prep.client;
  });

  itServer("Error: create order without required params", async () => {
    const date = new Date();
    date.setFullYear(date.getFullYear() + 1);
    await assert.rejects(
      testClient.newOrder({ identifiers: [] }), (err: AcmeError) => {
        assert.equal(!!testClient.lastNonce, true);
        assert.equal(err.type, errorType.malformed);
        assert.equal(err.status, 400);
        return true;
      });
  });

  it("create order", async () => {
    const params: any = { identifiers: [IDENTIFIER] };
    const res = await testClient.newOrder(params);
    assert.equal(!!res.link, true);
    assert.equal(!!testClient.lastNonce, true);
    assert.equal(res.status, 201);
    assert.equal(res.result.status, "pending");
    assert.equal(!!res.result.expires, true);
    assert.equal(!!res.result.authorizations, true);
  });

  it("re-request when sent invalid replay-nonce", async () => {
    testClient.lastNonce = "badNonce";
    const params: any = { identifiers: [IDENTIFIER] };
    const res = await testClient.newOrder(params);
    assert.equal(!!res.link, true);
    assert.equal(!!testClient.lastNonce, true);
    assert.equal(res.status, 201);
    assert.equal(res.result.status, "pending");
    assert.equal(!!res.result.expires, true);
    assert.equal(!!res.result.authorizations, true);
  });

  itServer("create duplicate order", async () => {
    const params: any = { identifiers: [IDENTIFIER] };
    const order1 = await testClient.newOrder(params);
    const order2 = await testClient.newOrder(params);
    assert.equal(order2.location, order1.location);
    assert.deepEqual(order1.result.authorizations.sort(), order2.result.authorizations.sort());
    assert.equal(order2.status, 201);
  });

  itServer("create new order with extended identifier", async () => {
    const params1: any = {
      identifiers: [
        { type: "dns", value: "test5.com" },
      ],
    };
    const order1 = await testClient.newOrder(params1);
    const params2: any = {
      identifiers: [
        { type: "dns", value: "test5.com" },
        { type: "dns", value: "test6.com" },
      ],
    };
    const order2 = await testClient.newOrder(params2);
    assert.notEqual(order1.location, order2.location);
    assert.equal(order2.result.authorizations.includes(order1.result.authorizations[0]), true);
    assert.equal(order2.status, 201);
  });

  itServer("create new order with one of the  identifier", async () => {
    const params1: any = {
      identifiers: [
        { type: "dns", value: "test3.com" },
        { type: "dns", value: "test4.com" },
      ],
    };
    const order1 = await testClient.newOrder(params1);
    const params2: any = {
      identifiers: [
        { type: "dns", value: "test3.com" },
      ],
    };
    const order2 = await testClient.newOrder(params2);
    assert.notEqual(order1.location, order2.location);
    assert.equal(order1.result.authorizations.includes(order2.result.authorizations[0]), true);
    assert.equal(order2.status, 201);
  });

  itServer("create new order with same identifiers", async () => {
    const params1: any = {
      identifiers: [
        { type: "dns", value: "test1.com" },
        { type: "dns", value: "test2.com" },
      ],
    };
    const order1 = await testClient.newOrder(params1);
    const params2: any = {
      identifiers: [
        { type: "dns", value: "test2.com" },
        { type: "dns", value: "test1.com" },
      ],
    };
    const order2 = await testClient.newOrder(params2);
    assert.equal(order1.location, order2.location);
    assert.deepEqual(order1.result.authorizations.sort(), order2.result.authorizations.sort());
    assert.equal(order2.status, 201);
  });
  
  it("authorization deactivation", async () => {
    const params: any = { identifiers: [{type: "dns", value: "identifier.com"}] };
    const order = await testClient.newOrder(params);
    const res = await testClient.deactivateAuthorization(order.result.authorizations[0]);
    assert.equal(res.result.status, "deactivated");
    assert.equal(res.status, 200);
  });

  itServer("Error: Account is not valid, has status deactivated", async () => {
    await testClient.deactivateAccount();
    const params: any = { identifiers: [IDENTIFIER] };
    await assert.rejects(testClient.newOrder(params), (err: AcmeError) => {
      assert.equal(!!testClient.lastNonce, true);
      assert.equal(err.status, 401);
      assert.equal(err.type, errorType.unauthorized);
      return true;
    });
  });

});
