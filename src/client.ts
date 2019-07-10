import jws from "jws";
import {Headers, Response} from "node-fetch";
import fetch from "node-fetch";
import * as core from "webcrypto-core";
import {crypto} from "./crypto";
import {
  Base64UrlString, IAccount, ICreateAccount,
  IDirectory, IError, IKeyChange, INewOrder, IToken, IUpdateAccount,
} from "./types";

export interface IAcmeClientOptions {
  /**
   * Private key for authentication
   */
  authKey: CryptoKey;
}

export interface ICreateJwsOptions {
  url?: string;
  kid?: string;
  omitNonce?: boolean;
  key?: CryptoKey;
}

export interface IPostResult<T = any> {
  status: number;
  result: T;
  error?: IError;
  headers: Headers;
}

export interface IAuthKey {
  key: CryptoKey;
  id?: Base64UrlString;
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

  public async createAccount(params: ICreateAccount): Promise<IPostResult<IAccount>> {
    const res = await this.post(this.getDirectory().newAccount, params);
    if (!res.error) {
      const location = res.headers.get("location");
      if (!location) {
        throw new Error("Cannot get Location header");
      }
      this.authKey.id = location;
    }
    return res;
  }

  public async updateAccount(params: IUpdateAccount): Promise<IPostResult<IAccount>> {
    return this.post(this.getKeyId(), params, {kid: this.getKeyId()});
  }

  public async changeKey(key?: CryptoKey): Promise<IPostResult<IAccount>> {
    const keyChange: IKeyChange = {
      account: this.getKeyId(),
      oldKey: await this.exportPublicKey(this.authKey.key),
    };
    const innerToken = await this.createJWS(keyChange, {omitNonce: true, url: this.getDirectory().keyChange, key});
    const res = await this.post(this.getDirectory().keyChange, innerToken, {kid: this.getKeyId()});
    if (!res.error) {
      this.authKey.key = key!;
    }
    return res;
  }

  public async deactivate(): Promise<IPostResult<IAccount>> {
    return this.post(this.getKeyId(), {status: "deactivated"}, {kid: this.getKeyId()});
  }

  public async post(url: string, params: any, options?: ICreateJwsOptions) {
    if (!this.lastNonce) {
      this.lastNonce = await this.nonce();
    }

    const token = await this.createJWS(params, Object.assign({url}, options));
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

  public async newOrder(params: INewOrder) {
    return this.post(this.getDirectory().newOrder, params, {kid: this.getKeyId()});
  }

  public async createJWS(payload: any, options: ICreateJwsOptions) {
    const key = options.key || this.authKey.key;
    const keyPem = await this.getKeyPem(key);
    const header: jws.Header = {
      alg: (key.algorithm.name === "ECDSA"
        ? `ES${(key.algorithm as EcKeyAlgorithm).namedCurve.replace("P-", "")}`
        : "RS256") as any,
    };
    if (!options.kid) {
      const jwk = await this.exportPublicKey(key);
      (header as any).jwk = jwk;
    } else {
      header.kid = options.kid;
    }
    if (options.url) {
      header.url = options.url;
    }
    if (!options.omitNonce) {
      header.nonce = this.lastNonce;
    }
    const signature = jws.sign({
      header,
      privateKey: keyPem,
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

  private async exportPublicKey(key: CryptoKey) {
    let jwk = await crypto.subtle.exportKey("jwk", key);
    delete jwk.d;
    const publicKey = await crypto.subtle.importKey("jwk", jwk, key.algorithm as any, true, ["verify"]);
    jwk = await crypto.subtle.exportKey("jwk", publicKey);
    delete jwk.alg;
    return jwk;
  }

  private async getKeyPem(key: CryptoKey) {
    const pkcs8 = await crypto.subtle.exportKey("pkcs8", key);
    return core.PemConverter.fromBufferSource(
      pkcs8,
      "PRIVATE KEY");
  }

  private getDirectory() {
    if (!this.directory) {
      throw new Error("Call 'initialize' method fist");
    }
    return this.directory;
  }

  private getKeyId() {
    if (!this.authKey.id) {
      throw new Error("Create or Find account first");
    }
    return this.authKey.id;
  }

  private getNonce(response: Response) {
    const res = response.headers.get("replay-nonce");
    if (!res) {
      throw new Error("Cannot get Replay-nonce header");
    }
    return res;
  }

}
