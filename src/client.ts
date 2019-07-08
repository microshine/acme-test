import jws from "jws";
import fetch from "node-fetch";
import {IDirectory} from "./types";

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

  public createJWS() {
    // jws.sign({
    //     privateKey: 
    // })
  }

}
