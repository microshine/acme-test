const pkijs = require("pkijs");
const asn1js = require("asn1js");

import { Crypto } from "@peculiar/webcrypto";

/**
 * Формирование CSR. Заказ на сертификат.
 * @param algorithm Алгоритм генерации ключа
 * @param domain Домен на который составляется заказ
 */
export async function generateCSR(algorithm: RsaHashedKeyGenParams | EcKeyGenParams, domain?: string) {

  const crypto = new Crypto();

  let pkcs10 = new pkijs.CertificationRequest();

  // Set engine
  pkijs.setEngine("Crypto", crypto, new pkijs.CryptoEngine({ name: "Crypto", crypto, subtle: crypto.subtle }));

  const {
    publicKey,
    privateKey,
  } = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);

  pkcs10.version = 0;
  // pkcs10 = decoratePkcs10Subject(pkcs10, data);
  if (domain) {
    pkcs10.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
      type: "2.5.4.3",
      value: new asn1js.PrintableString({ value: domain }),
    }));
  }
  pkcs10.attributes = [];

  await pkcs10.subjectPublicKeyInfo.importKey(publicKey);

  // const attribute = new pkijs.Attribute({
  //   type: "1.2.840.113549.1.9.14",
  //   values: [(new pkijs.Extensions({
  //     extensions: [
  //       new pkijs.Extension({
  //         extnID: "2.5.29.14",
  //         critical: false,
  //         extnValue: (new asn1js.OctetString({valueHex: hash})).toBER(false),
  //       }),
  //     ],
  //   })).toSchema()],
  // });

  // pkcs10.attributes.push(attribute);

  // sign
  await pkcs10.sign(privateKey, "SHA-256");

  // Fix parameters for algorithms
  if (!pkcs10.signatureAlgorithm.algorithmParams) {
    pkcs10.signatureAlgorithm.algorithmParams = new asn1js.Null();
  }
  const csr = pkcs10.toSchema().toBER(false);
  return {
    csr: Buffer.from(csr),
    privateKey,
    publicKey,
  };
}
