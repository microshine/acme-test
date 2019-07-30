import "colors";
import jws from "jws";
import { Response } from "node-fetch";
import fetch from "node-fetch";
import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";
import { errorType } from "../test/errors_type";
import { crypto } from "./crypto";
import { AcmeError } from "./error";
import {
  Base64UrlString, IAccount, ICreateAccount,
  IDirectory, IFinalize, IKeyChange, INewOrder, IOrder, IToken, IUpdateAccount,
} from "./types";
import { IAuthorization, IHttpChallenge } from "./types/authorization";
import { defineURL } from "./helper";

export enum RevocationReason {
  Unspecified = 0,
  KeyCompromise = 1,
  CACompromise = 2,
  AffiliationChanged = 3,
  Superseded = 4,
  CessationOfOperation = 5,
  CertificateHold = 6,
  RemoveFromCRL = 8,
  PrivilegeWithdrawn = 9,
  AACompromise = 10,
}

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

/**
 * Class of work with ACME servers
 */
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

  /**
   * Retrieving a list of controllers from an ACME server
   * @param url ACME Server Controller List Issue URL
   */
  public async initialize(url: string) {
    try {
      const response = await fetch(url, { method: "GET" });
      this.directory = await response.json();
      if (
        !this.directory
        || !defineURL(this.directory.keyChange)
        || !defineURL(this.directory.newAccount)
        || !defineURL(this.directory.newNonce)
        || !defineURL(this.directory.newOrder)
        || !defineURL(this.directory.revokeCert)
      ) {
        throw new AcmeError({type: errorType.malformed, status: 400, detail: ""});
      }

    } catch (error) {

    }
    return this.directory;
  }

  /**
   * Confirmation Code Request
   */
  public async nonce() {
    const response = await fetch(this.getDirectory().newNonce, { method: "GET" });
    return this.getNonce(response);
  }

  /**
   * Create account.
   * To create a new account, you must specify the termsOfServiceAgreed: true parameter.
   * To search for an account, you must specify the parameter onlyReturnExisting: true.
   * @param params Request parameters
   */
  public async createAccount(params: ICreateAccount) {
    const res = await this.request<IAccount>(this.getDirectory().newAccount, "POST", params, false);
    if (!res.location) {
      throw new Error("Cannot get Location header");
    }
    this.authKey.id = res.location;
    return res;
  }

  /**
   * Update account settings.
   * @param params Updateable parameters
   */
  public async updateAccount(params: IUpdateAccount) {
    return this.request<IAccount>(this.getKeyId(), "POST", params);
  }

  /**
   * Account key change
   * @param key New key
   */
  public async changeKey(key?: CryptoKey) {
    const keyChange: IKeyChange = {
      account: this.getKeyId(),
      oldKey: await this.exportPublicKey(this.authKey.key),
    };
    const innerToken = await this.createJWS(keyChange, { omitNonce: true, url: this.getDirectory().keyChange, key });
    const res = await this.request<IAccount>(this.getDirectory().keyChange, "POST", innerToken);
    if (key) {
      this.authKey.key = key;
    }
    return res;
  }

  /**
   * Certificate revocation.
   * @param certificate 
   * @param reason Reason for feedback
   */
  public async revoke(certificate: BufferSource, reason?: RevocationReason) {
    return this.request(this.getDirectory().revokeCert, "POST", {
      certificate: Convert.ToBase64Url(certificate),
      reason,
    });
  }

  /**
   * Account deactivation.
   * changes account status to deactivated
   */
  public async deactivateAccount() {
    return this.deactivate<IAccount>(this.getKeyId());
  }

  /**
   * Authorization deactivation.
   * changes authorization status to deactivated
   */
  public async deactivateAuthorization() {
    return this.deactivate<IAuthorization>(this.getKeyId());
  }

  /**
   * Deactivation Request
   * @param url Deactivation element URL
   */
  public async deactivate<T>(url: string) {
    return this.request<T>(url, "POST", { status: "deactivated" });
  }

  /**
   * Request for ACME server with error handling badNonce
   * @param url адресс сервера ACME
   * @param method default "GET"
   * @param params 
   * @param kid dafeult true
   */
  public async request<T>(
    url: string,
    method: Method = "GET",
    params?: any,
    kid: boolean = true): Promise<IPostResult<T>> {
    try {
      const res = await this.requestACME<T>(url, method, params, kid);
      return res;
    } catch (error) {
      if (error.type === errorType.badNonce) {
        try {
          const res = await this.requestACME<T>(url, method, params, kid);
          return res;
        } catch (err) {
          error = err;
        }
      }
      throw new AcmeError(error);
    }
  }

  /**
   * Request for ACME server
   * @param url адресс сервера ACME
   * @param method default "GET"
   * @param params 
   * @param kid dafeult true
   */
  public async requestACME<T>(
    url: string,
    method: Method = "GET",
    params?: any,
    kid: boolean = true): Promise<IPostResult<T>> {
    let response: Response;
    if (!this.lastNonce) {
      this.lastNonce = await this.nonce();
    }
    if (!params || method === "GET") {
      params = "";
    }
    const token = kid
      ? await this.createJWS(params, Object.assign({ url }, { kid: this.getKeyId() }))
      : await this.createJWS(params, Object.assign({ url }));
    response = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/jose+json",
      },
      body: JSON.stringify(token),
    });
    this.lastNonce = response.headers.get("replay-nonce") || "";

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
    const contentType = response.headers.get("content-type");
    if (contentType && contentType.includes("application/pem-certificate-chain")) {
      result = await response.text();
    } else if (contentType) {
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

  /**
   * Create a new order.
   * Returns an existing order if the identifiers parameter matches
   * @param params 
   */
  public async newOrder(params: INewOrder) {
    return this.request<IOrder>(this.getDirectory().newOrder, "POST", params);
  }

  /**
   * Getting data about challenge.
   * The POST method starts checking on the ACME server side.
   * @param url адресс сhallenge
   * @param method метод вызова
   */
  public async getChallenge(url: string, method: Method = "GET") {
    const res = await this.request<IHttpChallenge>(url, method, {}); //{}
    if (method === "POST") {
      await this.pause(2000);
    }
    return res;
  }

  /**
   * Order finalize
   * @param url 
   * @param params 
   */
  public async finalize(url: string, params: IFinalize) {
    return this.request<IOrder>(url, "POST", params);
  }

  /**
   * Retrieving Authorization Data
   * @param url адрес авторизации
   * @param method метод вызова
   */
  public async getAuthorization(url: string, method: Method = "GET") {
    return this.request<IAuthorization>(url, method);
  }

  /**
   * Obtaining a certificate of a complete order
   * @param url 
   * @param method 
   */
  public async getCertificate(url: string, method: Method = "POST") {
    const response = await this.request<string>(url, method);
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
   * Creation JWS.
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

  /**
   * Getting an account id.
   */
  public getKeyId() {
    if (!this.authKey.id) {
      throw new Error("Create or Find account first");
    }
    return this.authKey.id;
  }

  /**
   * Getting the public key.
   * @param key 
   */
  public async exportPublicKey(key?: CryptoKey) {
    key = key || this.authKey.key;
    let jwk = await crypto.subtle.exportKey("jwk", key);
    delete jwk.d;
    const publicKey = await crypto.subtle.importKey("jwk", jwk, key.algorithm as any, true, ["verify"]);
    jwk = await crypto.subtle.exportKey("jwk", publicKey);
    // delete jwk.alg;
    return jwk;
  }

  /**
   * Getting the secret key.
   * @param key 
   */
  private async getKeyPem(key: CryptoKey) {
    const pkcs8 = await crypto.subtle.exportKey("pkcs8", key);
    return core.PemConverter.fromBufferSource(
      pkcs8,
      "PRIVATE KEY");
  }

  /**
   * Returns a list of ACME server controllers.
   */
  private getDirectory() {
    if (!this.directory) {
      throw new Error("Call 'initialize' method fist");
    }
    return this.directory;
  }

  /**
   * Getting replay-nonce parameter response from the header
   * @param response 
   */
  private getNonce(response: Response) {
    const res = response.headers.get("replay-nonce");
    if (!res) {
      throw new Error("Cannot get replay-nonce header");
    }
    return res;
  }

  /**
   * Causes a time delay of a specified number of ms
   * @param ms 
   */
  private async pause(ms: number) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Logging responses from the ACME server
   * @param url 
   * @param res 
   * @param method 
   */
  private logResponse(url: string, res: any, method: string) {
    if (this.debug) {
      console.log(`${method} RESPONSE ${url}`.blue);
      console.log("Result", res);
    }
  }
}
