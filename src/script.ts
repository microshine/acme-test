import "colors";
import fetch from "node-fetch";
import {Convert} from "pvtsutils";
import {PemConverter} from "webcrypto-core";
import {crypto} from "../src/crypto";
import {generateCSR} from "../test/csr";
import {AcmeClient} from "./client";
import {IHttpChallenge} from "./types/authorization";

export interface ICetrOptions {
  url: string;
  domain: string;
  keys?: CryptoKeyPair;
  algorithm?: RsaHashedKeyGenParams;
  contact: string[];
}

export async function getCertificate(options: ICetrOptions) {
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

  const client = new AcmeClient({authKey: options.keys.privateKey});
  await client.initialize(options.url);
  const account = await client.createAccount({
    contact: options.contact,
    termsOfServiceAgreed: true,
  });

  const date = new Date();
  date.setFullYear(date.getFullYear() + 1);
  const params: any = {
    identifiers: [{type: "dns", value: options.domain}],
  };
  // params.notAfter = date.toISOString();
  // params.notBefore = new Date().toISOString();
  let order = (await client.newOrder(params)).result;
  const authorization = (await client.getAuthorization(order.authorizations[0])).result;
  let challange = authorization.challenges.filter((o) => o.type === "http-01")[0] as IHttpChallenge;

  //#region создание ссылки на тестовом сервере
  const json = JSON.stringify(account.result.key, Object.keys(account.result.key).sort());
  await client.createURL(
    "http://aeg-dev0-srv.aegdomain2.com/acme-challenge", challange.token,
    Convert.ToBase64Url(await crypto.subtle.digest("SHA-256", Buffer.from(json))),
  );
  //#endregion

  await client.getChallenge(challange.url, "post");
  const csr = await generateCSR(options.algorithm, options.domain);
  const finalize = (await client.finalize(order.finalize, {csr: Convert.ToBase64Url(csr.csr)})).result;
  if (!finalize.certificate) {
    throw new Error("No certificate link");
  }
  const res = await fetch(finalize.certificate, {method: "GET"});
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
  console.log("CERT".green, matches[1]);
}

const test: ICetrOptions = {
  url: "https://acme-staging-v02.api.letsencrypt.org/directory",
  domain: "aeg-dev0-srv.aegdomain2.com",
  contact: ["mailto:microshine@mail.ru"],
};

getCertificate(test);
