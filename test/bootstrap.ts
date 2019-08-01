
import { config as env } from "dotenv";
env();
import * as assert from "assert";
import fetch from "node-fetch";
import { Convert } from "pvtsutils";
import { AcmeClient, IPostResult } from "../src/client";
import { crypto } from "../src/crypto";
import { IAccount, IOrder } from "../src/types";
import { IAuthorization, IHttpChallenge } from "../src/types/authorization";

process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0";

export const URL_SERVER = process.env["URL_SERVER"] || "";
export const ALGORITHM: RsaHashedKeyGenParams = {
  name: process.env["ALG_NAME"] || "",
  hash: process.env["ALG_HASH"] || "",
  publicExponent: new Uint8Array([1, 0, 1]),
  modulusLength: Number(process.env["ALG_MODULUS_LENGTH"] || ""),
};
export const IDENTIFIER = {
  type: process.env["IDENTIFIER_TYPE"] || "",
  value: process.env["IDENTIFIER_VALUE"] || "",
};
export const CONTACT = process.env["CONTACT"] || "";

const serverTesting: boolean = process.env["SERVER_TESTING"] === "true" ? true : false;
export const contextServer = serverTesting ? context.only : context;
export const contextClient = serverTesting ? context : context.only;

export interface IPreparation {
  client: AcmeClient;
  account: IAccount | undefined;
  order: IOrder | undefined;
}

export function checkHeaders(client: AcmeClient, res: IPostResult<any>) {
  assert.equal(!!res.link, true);
  assert.equal(!!res.location, true);
  assert.equal(!!client.lastNonce, true);
}
export function checkResAccount(res: any, status: number) {
  assert.equal(res.result.status, "valid");
  assert.equal(res.status, status);
}

/**
 * Creates a time delay
 * @param ms 
 */
export async function pause(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Auxiliary element initialization function.
 * Generates the authKey, initializes the client.
 * @param client 
 * @param authKey 
 * @param newAccount 
 * @param newOrder 
 */
export async function preparation(newAccount?: boolean, newOrder?: boolean) {
  // const acmeKey = process.env.ACME_KEY;
  // assert.equal(!!acmeKey, true, "Environment variable ACME_KEY does not exist");
  // authKey = await crypto.subtle.importKey("pkcs8", Buffer.from(acmeKey!, "base64"), rsaAlg, true, ["sign"]);

  let order: IOrder | undefined;
  let account: IAccount | undefined;
  const keys = await crypto.subtle.generateKey(ALGORITHM, true, ["sign", "verify"]);
  const client = new AcmeClient({ authKey: keys.privateKey, debug: !!process.env["ACME_DEBUG"] });
  await client.initialize(URL_SERVER);

  if (newAccount) {
    const res = await client.createAccount({
      contact: [CONTACT],
      termsOfServiceAgreed: true,
    });
    account = res.result;
  }

  if (newOrder) {
    const params: any = { identifiers: [IDENTIFIER] };
    const res = await client.newOrder(params);
    order = res.result;
  }
  return {
    client,
    account,
    order,
  };
}

/**
 * Creates a controller on a test server to check for accessibility by identifier.
 * @param authorization 
 * @param client 
 */
export async function createURL(client: AcmeClient, authorization: IAuthorization) {
  const challange = authorization.challenges.filter((o) => o.type === "http-01")[0] as IHttpChallenge;
  const account = await client.createAccount({ onlyReturnExisting: true });
  // const json = JSON.stringify(account.result.key, Object.keys(account.result.key));
  delete account.result.key.alg;
  const json = JSON.stringify(account.result.key, Object.keys(account.result.key).sort());
  const id = challange.token;
  const token = Convert.ToBase64Url(await crypto.subtle.digest("SHA-256", Buffer.from(json)));
  const body = JSON.stringify({ id, token: `${id}.${token}` });
  const res = await fetch("http://aeg-dev0-srv.aegdomain2.com/acme-challenge", {
    method: "post",
    headers: {
      "content-type": "application/json",
    },
    body,
  });
  if (res.status !== 204) {
    throw new Error(await res.text());
  }
}
