import "colors";
import jws from "jws";
import {Response} from "node-fetch";
import fetch from "node-fetch";
import * as core from "webcrypto-core";
import {crypto} from "./crypto";
import {AcmeError} from "./error";
import {
  Base64UrlString, IAccount, ICreateAccount,
  IDirectory, IFinalize, IKeyChange, INewOrder, IOrder, IToken, IUpdateAccount,
} from "./types";
import {IAuthorization, IHttpChallenge} from "./types/authorization";

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

export interface IPostResult<T = any> extends IHeaders {
  status: number;
  result: T;
}

export interface IHeaders {
  link?: string | string[];
  location?: string;
}

export interface IAuthKey {
  key: CryptoKey;
  id?: Base64UrlString;
}

type Method = "POST" | "GET";

export class AcmeClient {

  public lastNonce: string = "";
  public directory?: IDirectory;
  public authKey: IAuthKey;
  private debug: boolean;

  constructor(options: IAcmeClientOptions) {
    this.authKey = {
      key: options.authKey,
    };
    this.debug = !!options.debug;
  }

  public async initialize(url: string) {
    const response = await fetch(url, {method: "GET"});
    this.directory = await response.json();
    return this.directory;
  }

  public async nonce() {
    const response = await fetch(this.getDirectory().newNonce, {method: "GET"});
    return this.getNonce(response);
  }

  public async createAccount(params: ICreateAccount) {
    const res = await this.request<IAccount>(this.getDirectory().newAccount, "POST", params, false);
    if (!res.location) {
      throw new Error("Cannot get Location header");
    }
    this.authKey.id = res.location;
    return res;
  }

  public async updateAccount(params: IUpdateAccount) {
    return this.request<IAccount>(this.getKeyId(), "POST", params);
  }

  public async changeKey(key?: CryptoKey) {
    const keyChange: IKeyChange = {
      account: this.getKeyId(),
      oldKey: await this.exportPublicKey(this.authKey.key),
    };
    const innerToken = await this.createJWS(keyChange, {omitNonce: true, url: this.getDirectory().keyChange, key});
    const res = await this.request<IAccount>(this.getDirectory().keyChange, "POST", innerToken);
    if (key) {
      this.authKey.key = key;
    }
    return res;
  }

  public async deactivateAccount() {
    return this.deactivate<IAccount>(this.getKeyId());
  }

  public async deactivateAuthorization() {
    return this.deactivate<IAuthorization>(this.getKeyId());
  }

  public async deactivate<T>(url: string) {
    return this.request<T>(url, "POST", {status: "deactivated"});
  }

  public async createURL(url: string, id: string, token: string) {
    const body = JSON.stringify({id, token: `${id}.${token}`});
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

  /**
   * Запрос на сервер
   * @param url адресс сервера
   * @param method default "GET"
   * @param params 
   * @param options 
   * @param kid 
   */
  public async request<T>(
    url: string,
    method: Method = "GET",
    params?: any,
    kid: boolean = true): Promise<IPostResult<T>> {
    let response: Response;
    if (method === "POST") {
      if (!this.lastNonce) {
        this.lastNonce = await this.nonce();
      }
      const token = kid
        ? await this.createJWS(params, Object.assign({url}, {kid: this.getKeyId()}))
        : await this.createJWS(params, Object.assign({url}));
      response = await fetch(url, {
        method,
        headers: {
          "content-type": "application/jose+json",
        },
        body: JSON.stringify(token),
      });
      this.lastNonce = response.headers.get("replay-nonce") || "";
    } else {
      response = await fetch(url, {method});
    }
    const headers: IHeaders = {
      link: response.headers.get("link") || undefined,
      location: response.headers.get("location") || undefined,
    };
    if (!(response.status >= 200 && response.status < 300)) {
      // TODO: throw exception
      // TODO: Detect ACME exception
      const error = await response.text();
      let errJson: any;
      try {
        errJson = JSON.parse(error);
        this.logResponse(url, errJson, method);
      } catch {
        throw new Error(error);
      }
      throw new AcmeError(errJson);
    }
    let result: any;
    if (response.headers.get("content-type") === "application/pem-certificate-chain") {
      result = await response.text();
    } else {
      result = await response.json();
    }
    const res: IPostResult = {
      status: response.status,
      ...headers,
      result,
    };

    this.logResponse(url, res, method);

    return res;
  }

  public async newOrder(params: INewOrder) {
    return this.request<IOrder>(this.getDirectory().newOrder, "POST", params);
  }

  public async getChallenge(url: string, method: Method = "GET") {
    const res = await this.request<IHttpChallenge>(url, method, {});
    if (method === "POST") {
      await this.pause(2000);
    }
    return res;
  }

  public async finalize(url: string, params: IFinalize) {
    return this.request<IOrder>(url, "POST", params);
  }

  public async getAuthorization(url: string, method: Method = "POST") {
    return this.request<IAuthorization>(url, method, "");
  }

  public async getCertificate(url: string) {
    const response = await this.request<string>(url);
    const certs: string[] = [];
    const regex = /(-----BEGIN CERTIFICATE-----[a-z0-9\/+=\n]+-----END CERTIFICATE-----)/gmis;
    let matches: RegExpExecArray | null = null;
    while (matches = regex.exec(response.result)) {
      certs.push(matches[1]);
    }
    const res: IPostResult<string[]> = {
      link: response.link,
      location: response.location,
      result: certs,
      status: response.status,
    };
    return res;
  }

  /**
   * Создание JWS
   * @param payload 
   * @param options 
   */
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

  private async pause(ms: number) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  private logResponse(url: string, res: any, method: string) {
    if (this.debug) {
      console.log(`${method} RESPONSE ${url}`.blue);
      console.log("Result", res);
    }
  }
}
