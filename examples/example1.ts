import "colors";
import {Convert} from "pvtsutils";
import {PemConverter} from "webcrypto-core";
import {AcmeClient} from "../src/client";
import {crypto} from "../src/crypto";
import {IHttpChallenge} from "../src/types/authorization";
import {generateCSR} from "../test/csr";

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
  const client = new AcmeClient({authKey: options.keys.privateKey});
  const directory = await client.initialize(options.url);
  console.log("Directory:".yellow);
  console.log(directory);
  const account = await client.createAccount({
    contact: options.contact,
    termsOfServiceAgreed: true,
  });
  console.log("Account:".yellow);
  console.log(account.result);

  const params: any = {
    identifiers: [{type: "dns", value: options.domain}],
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
  await client.createURL(
    "http://aeg-dev0-srv.aegdomain2.com/acme-challenge", challange.token,
    Convert.ToBase64Url(await crypto.subtle.digest("SHA-256", Buffer.from(json))),
  );
  //#endregion

  await client.getChallenge(challange.url, "POST");
  const csr = await generateCSR(options.algorithm, options.domain);
  const finalize = (await client.getFinalize(order.result.finalize, {csr: Convert.ToBase64Url(csr.csr)})).result;
  if (!finalize.certificate) {
    throw new Error("No certificate link");
  }
  const res = await client.getCertificate(finalize.certificate);
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
  url: "https://acme-staging-v02.api.letsencrypt.org/directory",
  domain: "aeg-dev0-srv.aegdomain2.com",
  contact: ["mailto:microshine@mail.ru"],
};

main(test).catch((err) => console.error(err));
