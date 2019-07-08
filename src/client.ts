import jws from "jws";
import fetch from "node-fetch";
import * as core from "webcrypto-core";
import { crypto } from "./crypto";
import { IDirectory } from "./types";


export interface IAcmeClientOptions {
  /**
   * Private key for authentication
   */
  authKey: CryptoKey;
}

export class AcmeClient {

  private directory?: IDirectory;
  private lastNonce: string = "";
  private authKey: CryptoKey;
  private authKeyPem?: string;

  constructor(options: IAcmeClientOptions) {
    this.authKey = options.authKey;
  }

  public async initialize(url: string) {
    try {
      const response = await fetch(url, {
        method: "GET",
      });
      this.directory = await response.json();
      if (this.directory) {
        return;
      }
    } catch (error) {
      return error;
    }
  }

  public async nonce() {
    if (!this.directory) {
      throw new Error("Call 'initialize' method fist");
    }

    const response = await fetch(this.directory.newNonce, {
      method: "GET",
    });

    return response.headers.get("replay-nonce");
  }

  public async createAccount(params: any) {
    if (!this.lastNonce) {
      await this.nonce();
    }

  }

  public async createJWS(payload: any) {
    const token = jws.sign({
        header: {
          alg: (this.authKey.algorithm.name === "ECDSA"
          ? `ES${(this.authKey.algorithm as EcKeyAlgorithm).namedCurve.replace("P-", "")}`
          : "RS256") as any,
        },
        privateKey: await this.getKeyPem(),
        payload,
    });
    return token;
  }

  private async getKeyPem() {
    if (!this.authKeyPem) {
      const pkcs8 = await crypto.subtle.exportKey("pkcs8", this.authKey);
      this.authKeyPem = core.PemConverter.fromBufferSource(
        pkcs8,
        this.authKey.algorithm.name === "ECDSA"
          ? "ECDSA PRIVATE KEY"
          : "RSA PRIVATE KEY");
    }
    return this.authKeyPem;
  }

}
