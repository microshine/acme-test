import "colors";
import fetch from "node-fetch";
import { Convert } from "pvtsutils";
import { PemConverter } from "webcrypto-core";
import { AcmeClient } from "../src/client";
import { crypto } from "../src/crypto";
import { IHttpChallenge } from "../src/types/authorization";
import { generateCSR } from "../test/csr";

// tslint:disable: no-console

export interface ICertificateOptions {
  url: string;
  domain: string;
  keys?: CryptoKeyPair;
  algorithm?: RsaHashedKeyGenParams;
  contact: string[];
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
  }

  const client = new AcmeClient({ authKey: options.keys.privateKey });
  await client.initialize(options.url);
  const account = await client.createAccount({
    contact: options.contact,
    termsOfServiceAgreed: true,
  });

  const params: any = {
    identifiers: [{ type: "dns", value: options.domain }],
  };

  const order = (await client.newOrder(params)).result;
  const authorization = (await client.getAuthorization(order.authorizations[0])).result;
  const challange = authorization.challenges.filter((o) => o.type === "http-01")[0] as IHttpChallenge;

  //#region создание ссылки на тестовом сервере
  const json = JSON.stringify(account.result.key, Object.keys(account.result.key).sort());
  await client.createURL(
    "http://aeg-dev0-srv.aegdomain2.com/acme-challenge", challange.token,
    Convert.ToBase64Url(await crypto.subtle.digest("SHA-256", Buffer.from(json))),
  );
  //#endregion

  await client.getChallenge(challange.url, "post");
  const csr = await generateCSR(options.algorithm, options.domain);
  const finalize = (await client.finalize(order.finalize, { csr: Convert.ToBase64Url(csr.csr) })).result;
  if (!finalize.certificate) {
    throw new Error("No certificate link");
  }
  const res = await fetch(finalize.certificate, { method: "GET" });
  const certs = await res.text();
  const privateKey = await crypto.subtle.exportKey("pkcs8", options.keys.privateKey);
  const publicKey = await crypto.subtle.exportKey("spki", options.keys.publicKey);

  const regex = /(-----BEGIN CERTIFICATE-----[a-z0-9\/+=\n]+-----END CERTIFICATE-----)/gmis;
  const matches = regex.exec(certs);
  if (!matches) {
    throw new Error("Not come certificate");
  }
  console.log("PRIVATE KEY".green, PemConverter.fromBufferSource(privateKey, "PRIVATE KEY"));
  console.log("PUBLIC KEY".green, PemConverter.fromBufferSource(publicKey, "PUBLIC KEY"));
  console.log("END-ENTITY".green, matches[1]);
}

const test: ICertificateOptions = {
  url: "https://acme-staging-v02.api.letsencrypt.org/directory",
  domain: "aeg-dev0-srv.aegdomain2.com",
  contact: ["mailto:microshine@mail.ru"],
};

main(test).catch((err) => console.error(err));
