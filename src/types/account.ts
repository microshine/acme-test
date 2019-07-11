import {URL} from "./directory";

export interface IAccount {
  status: "valid" | "deactivated" | "revoked";
  contact?: string[];
  termsOfServiceAgreed?: boolean;
  orders: URL;
  key: {
    e: string;
    kty: string;
    n: string;
  };
}

export interface ICreateAccount {
  contact?: string[];
  termsOfServiceAgreed?: boolean;
  onlyReturnExisting?: boolean;
  externalAccountBinding?: object;
}

export interface IUpdateAccount {
  contact: string[];
}

export interface IKeyChange {
  account: string;
  oldKey: JsonWebKey;
}
