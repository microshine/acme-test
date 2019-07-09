import jws from "jws";
import { Headers, Response } from "node-fetch";
import fetch from "node-fetch";
import * as core from "webcrypto-core";
import { crypto } from "./crypto";
import { AcmeError } from "./error";
import {
  Base64UrlString, IAccount, ICreateAccount,
  IDirectory, IError, IToken, IUpdateAccount,
} from "./types";

export interface IAcmeClientOptions {
  /**
   * Private key for authentication
   */
  authKey: CryptoKey;
}

export interface ICreateJwsOptions {
  url?: string;
  useJwk?: boolean;
}

export interface IPostResult {
  status: number;
  result: any;
  error?: IError;
  headers: Headers;
}

export interface IAuthKey {
  key: CryptoKey;
  id?: Base64UrlString;
  pem?: string;
}

export class AcmeClient {

  private directory?: IDirectory;
  private lastNonce: string = "";
  private authKey: IAuthKey;

  constructor(options: IAcmeClientOptions) {
    this.authKey = {
      key: options.authKey,
    };
  }

  public async initialize(url: string) {
    const response = await fetch(url, {
      method: "GET",
    });
    this.directory = await response.json();
    return this.directory;
  }

  public async nonce() {
    const response = await fetch(this.getDirectory().newNonce, {
      method: "GET",
    });
    return this.getNonce(response);
  }

  public async createAccount(params: ICreateAccount): Promise<IAccount> {
    const res = await this.post(this.getDirectory().newAccount, params, { useJwk: true });
    if (!res.error) {
      const location = res.headers.get("location");
      if (!location) {
        throw new Error("Cannot get Location header");
      }
      this.authKey.id = location;
      return res.result;
    } else {
      throw new AcmeError(res.error);
    }
  }

  public async findAccount(): Promise<IAccount | null> {
    const params: ICreateAccount = { onlyReturnExisting: true };
    const res = await this.post(this.getDirectory().newAccount, params, { useJwk: true });
    if (!res.error) {
      const location = res.headers.get("location");
      if (!location) {
        throw new Error("Cannot get Location header");
      }
      this.authKey.id = location;
      return res.result;
    } else {
      // TODO: check headers and status
      return null;
    }
  }

  public async updateAccount(params: IUpdateAccount): Promise<IAccount> {
    if (!this.authKey.id) {
      throw new Error("Create of Find account first");
    }
    const res = await this.post(this.authKey.id, params);
    if (!res.error) {
      return res.result;
    } else {
      throw new AcmeError(res.error);
    }
  }

  public async post(url: string, params: any, options?: ICreateJwsOptions) {
    if (!this.lastNonce) {
      this.lastNonce = await this.nonce();
    }

    const token = await this.createJWS(params, options || { url });
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/jose+json",
      },
      body: JSON.stringify(token),
    });

    if (!(response.status >= 200 && response.status < 300)) {
      // TODO: throw exception
      // TODO: Detect ACME exception
      const error = await response.text();
      this.lastNonce = response.headers.get("replay-nonce") || "";
      try {
        const errJson = JSON.parse(error);
        const errRes: IPostResult = {
          headers: response.headers,
          error: errJson,
          status: response.status,
          result: null,
        };
        return errRes;
      } catch {
        throw new Error(error);
      }
    }
    this.lastNonce = this.getNonce(response);
    const json = await response.json();
    const res: IPostResult = {
      headers: response.headers,
      result: json,
      status: response.status,
    };
    return res;
  }

  public async createJWS(payload: any, options: ICreateJwsOptions) {
    const key = await this.getKeyPem();
    const header: jws.Header = {
      alg: (this.authKey.key.algorithm.name === "ECDSA"
        ? `ES${(this.authKey.key.algorithm as EcKeyAlgorithm).namedCurve.replace("P-", "")}`
        : "RS256") as any,
    };
    if (options.useJwk) {
      let jwk = await crypto.subtle.exportKey("jwk", this.authKey.key);
      delete jwk.d;
      const publicKey = await crypto.subtle.importKey("jwk", jwk, this.authKey.key.algorithm as any, true, ["verify"]);
      jwk = await crypto.subtle.exportKey("jwk", publicKey);
      delete jwk.alg;
      (header as any).jwk = jwk;
    }
    if (options.url) {
      header.url = options.url;
    }
    header.nonce = this.lastNonce;
    const signature = jws.sign({
      header,
      privateKey: key,
      payload,
    });

    const parts = signature.split(".");
    const res: IToken = {
      protected: parts[0],
      payload: parts[1],
      signature: parts[2],
    };
    // console.log(`${res.protected}.${res.payload}.${res.signature}`);
    return res;
  }

  private async getKeyPem() {
    if (!this.authKey.pem) {
      const pkcs8 = await crypto.subtle.exportKey("pkcs8", this.authKey.key);
      this.authKey.pem = core.PemConverter.fromBufferSource(
        pkcs8,
        "PRIVATE KEY");
    }
    return this.authKey.pem;
  }

  private getDirectory() {
    if (!this.directory) {
      throw new Error("Call 'initialize' method fist");
    }
    return this.directory;
  }

  private getNonce(response: Response) {
    const res = response.headers.get("replay-nonce");
    if (!res) {
      throw new Error("Cannot get Replay-nonce header");
    }
    return res;
  }

}
