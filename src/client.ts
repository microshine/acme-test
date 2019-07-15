import "colors";
import jws from "jws";
import { Headers, Response } from "node-fetch";
import fetch from "node-fetch";
import * as util from "util";
import * as core from "webcrypto-core";
import { crypto } from "./crypto";
import {
  Base64UrlString, IAccount, ICreateAccount,
  IDirectory, IError, IFinalize, IKeyChange, INewOrder, IOrder, IToken, IUpdateAccount,
} from "./types";
import { IAuthorization, IChallenge, IHttpChallenge } from "./types/authorization";

export interface IAcmeClientOptions {
  /**
   * Private key for authentication
   */
  authKey: CryptoKey;
  debug?: boolean;
}

export interface ICreateJwsOptions {
  url?: string;
  kid?: string;
  omitNonce?: boolean;
  key?: CryptoKey;
}

export interface IGetOptions {
  hostname?: string;
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

type Method = "post" | "get";

export class AcmeClient {

  private directory?: IDirectory;
  private lastNonce: string = "";
  private authKey: IAuthKey;
  private debug: boolean;

  constructor(options: IAcmeClientOptions) {
    this.authKey = {
      key: options.authKey,
    };
    this.debug = !!options.debug;
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
    return this.post(this.getKeyId(), params, { kid: this.getKeyId() });
  }

  public async changeKey(key?: CryptoKey): Promise<IPostResult<IAccount>> {
    const keyChange: IKeyChange = {
      account: this.getKeyId(),
      oldKey: await this.exportPublicKey(this.authKey.key),
    };
    const innerToken = await this.createJWS(keyChange, { omitNonce: true, url: this.getDirectory().keyChange, key });
    const res = await this.post(this.getDirectory().keyChange, innerToken, { kid: this.getKeyId() });
    if (!res.error) {
      this.authKey.key = key!;
    }
    return res;
  }

  public async deactivate(): Promise<IPostResult<IAccount>> {
    return this.post(this.getKeyId(), { status: "deactivated" }, { kid: this.getKeyId() });
  }

  public async createURL(url: string, id: string, token: string) {
    const body = JSON.stringify({ id, token: `${id}.${token}` });
    const res = await fetch(url, {
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

  public async post(url: string, params: any, options?: ICreateJwsOptions) {
    if (!this.lastNonce) {
      this.lastNonce = await this.nonce();
    }

    const token = await this.createJWS(params, Object.assign({ url }, options));
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
        this.logResponse(url, errRes, "POST");
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

    this.logResponse(url, res, "POST");

    return res;
  }

  public async get(url: string) {
    const response = await fetch(url, { method: "get" });
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
        this.logResponse(url, errRes, "GET");
        return errRes;
      } catch {
        throw new Error(error);
      }
    }
    const json = await response.json();
    const res: IPostResult = {
      headers: response.headers,
      result: json,
      status: response.status,
    };

    this.logResponse(url, res, "GET");

    return res;
  }

  public async newOrder(params: INewOrder): Promise<IPostResult<IOrder>> {
    return this.post(this.getDirectory().newOrder, params, { kid: this.getKeyId() });
  }

  public async getChallenge(url: string, method: Method = "post"): Promise<IPostResult<IHttpChallenge>> {
    if (method === "post") {
      return this.post(url, {}, { kid: this.getKeyId() });
    }
    return this.get(url);
  }

  public async getCertificate(url: string): Promise<IPostResult<string[]>> {
    const response = await fetch(url, { method: "get" });
    if (response.status === 200) {
      const text = await response.text();

      const certs: string[] = [];
      const regex = /(-----BEGIN CERTIFICATE-----[a-z0-9\/+=\n]+-----END CERTIFICATE-----)/gmis;
      let matches: RegExpExecArray | null = null;
      while (matches = regex.exec(text)) {
        certs.push(matches[1]);
      }
      const res: IPostResult<string[]> = {
        headers: response.headers,
        result: certs,
        status: response.status,
      };
      this.logResponse(url, res, "get");
      return res;
    } else {
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
        this.logResponse(url, errRes, "GET");
        return errRes;
      } catch {
        throw new Error(error);
      }
    }
  }

  public async finalize(url: string, params: IFinalize): Promise<IPostResult<IOrder>> {
    return this.post(url, params, { kid: this.getKeyId() });
  }

  public async getAuthorization(url: string, method: Method = "post"): Promise<IPostResult<IAuthorization>> {
    if (method === "post") {
      return this.post(url, "", { kid: this.getKeyId() });
    }
    return this.get(url);
  }

  public async createJWS(payload: any, options: ICreateJwsOptions) {
    const key = options.key || this.authKey.key;
    const keyPem = key.algorithm.name === "HMAC"
      ? Buffer.from(await crypto.subtle.exportKey("raw", key))
      : await this.getKeyPem(key);
    const header: jws.Header = {
      alg: (key.algorithm.name === "ECDSA"
        ? `ES${(key.algorithm as EcKeyAlgorithm).namedCurve.replace("P-", "")}`
        : key.algorithm.name === "HMAC"
          ? "HS256"
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
    return res;
  }

  public getKeyId() {
    if (!this.authKey.id) {
      throw new Error("Create or Find account first");
    }
    return this.authKey.id;
  }

  public async exportPublicKey(key?: CryptoKey) {
    key = key || this.authKey.key;
    let jwk = await crypto.subtle.exportKey("jwk", key || this.authKey.key);
    delete jwk.d;
    const publicKey = await crypto.subtle.importKey("jwk", jwk, key.algorithm as any, true, ["verify"]);
    jwk = await crypto.subtle.exportKey("jwk", publicKey);
    // delete jwk.alg;
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

  private getNonce(response: Response) {
    const res = response.headers.get("replay-nonce");
    if (!res) {
      throw new Error("Cannot get Replay-nonce header");
    }
    return res;
  }

  private logResponse(url: string, res: IPostResult<any>, method: string) {
    if (this.debug) {
      console.log(`${method} RESPONSE ${url}`.blue);
      console.log("Status:", res.status);
      console.log("Headers:".yellow, util.inspect({
        Location: res.headers.get("location"),
        Link: res.headers.get("link"),
      }, false, 10, true));
      if (res.error) {
        console.log("Error:".red, util.inspect(res.error, false, 10, true));
      } else {
        console.log("Body:".yellow, util.inspect(res.result, false, 10, true));
      }
    }
  }

}
