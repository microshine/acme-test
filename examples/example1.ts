import { config as env } from "dotenv";
env();

import "colors";
import { Convert } from "pvtsutils";
import { PemConverter } from "webcrypto-core";
import { AcmeClient, IPostResult } from "../src/client";
import { crypto } from "../src/crypto";
import { IHttpChallenge } from "../src/types/authorization";
import { generateCSR } from "../test/csr";
import { IOrder, IExternalAccountBinding } from "../src/types";

export interface ICertificateOptions {
  url: string;
  domain: string;
  keys?: CryptoKeyPair;
  algorithm?: RsaHashedKeyGenParams;
  contact: string[];
  yearsValid?: number;
}

export async function main(options: ICertificateOptions) {
  if (!options.algorithm) {
    options.algorithm = {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
      publicExponent: new Uint8Array([1, 0, 1]),
      modulusLength: 2048,
    };
  }
  if (!options.keys) {
    options.keys = await crypto.subtle.generateKey(options.algorithm, true, ["sign", "verify"]);
    console.log("Generated new keys: completed".yellow);
  }
  const client = new AcmeClient({ authKey: options.keys.privateKey, debug: true });
  const directory = await client.initialize(options.url);
  console.log("Directory:".yellow);
  console.log(directory);

  // Create externalAccountBinding
  let externalAccountBinding: IExternalAccountBinding | undefined;
  if (process.env.ACCOUNT_CHALLENGE && process.env.ACCOUNT_KID) {
    externalAccountBinding = {
      challenge: process.env.ACCOUNT_CHALLENGE,
      kid: process.env.ACCOUNT_KID
    }
  }

  const account = await client.createAccount({
    contact: options.contact,
    termsOfServiceAgreed: true,
    externalAccountBinding,
  });
  console.log("Account:".yellow);
  console.log(account.result);

  const params: any = {
    identifiers: [{ type: "dns", value: options.domain }],
  };
  const date = new Date();
  if (options.yearsValid) {
    date.setFullYear(date.getFullYear() + options.yearsValid);
    params.notAfter = date.toISOString();
    params.notBefore = new Date().toISOString();
  }
  const order = (await client.newOrder(params));
  console.log("Order link:".yellow, order.location);
  const authorization = (await client.getAuthorization(order.result.authorizations[0])).result;
  console.log("Authorization:".yellow);
  console.log(authorization);
  const challange = authorization.challenges.filter((o) => o.type === "http-01")[0] as IHttpChallenge;

  //#region создание ссылки на тестовом сервере
  delete account.result.key.alg;
  const json = JSON.stringify(account.result.key, Object.keys(account.result.key).sort());
  const thumb = Convert.ToBase64(await crypto.subtle.digest("SHA-256", Buffer.from(json)));
  console.log(json);
  console.log(thumb);
  /*
  await client.createURL(
    "http://aeg-dev0-srv.aegdomain2.com/acme-challenge", challange.token,
    Convert.ToBase64Url(await crypto.subtle.digest("SHA-256", Buffer.from(json))),
  );
  */
  //#endregion

  await client.getChallenge(challange.url, "POST");
  const csr = await generateCSR(options.algorithm, options.domain);
  console.log(Convert.ToBase64Url(csr.csr));
  const finalize = (await client.finalize(order.result.finalize, { csr: Convert.ToBase64Url(csr.csr) })).result;
  // Poll certificate status
  let orderStatus: IPostResult<IOrder>;
  do {
    orderStatus = await client.request(order.location!, "GET");
    await client.pause(2000);
  } while (!(orderStatus.result.status === "valid" || orderStatus.result.status === "invalid"));

  if (orderStatus.result.status === "invalid") {
    console.error(`Cannot enroll certificate. ${order.result.errors!.detail}`);
    return;
  }
  // Get enrolled certificate
  const res = await client.getCertificate(orderStatus.result.certificate!);
  console.log("Certificate enrolled".green);
  const privateKey = await crypto.subtle.exportKey("pkcs8", options.keys.privateKey);
  const publicKey = await crypto.subtle.exportKey("spki", options.keys.publicKey);
  console.log("PRIVATE KEY".yellow);
  console.log(PemConverter.fromBufferSource(privateKey, "PRIVATE KEY"));
  console.log("PUBLIC KEY".yellow);
  console.log(PemConverter.fromBufferSource(publicKey, "PUBLIC KEY"));
  console.log("Link for download cert:".yellow, finalize.certificate);
  console.log("CERT".yellow);
  console.log(res.result[0]);
}

const test: ICertificateOptions = {
  url: process.env.URL_SERVER!,
  domain: process.env.IDENTIFIER_VALUE!,
  contact: ["mailto:microshine@mail.ru"],
};

main(test).catch((err) => console.error(err));
