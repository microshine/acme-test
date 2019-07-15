import {URL} from "./directory";
import { IToken } from "./token";

export interface IAccount {
  status: "valid" | "deactivated" | "revoked";
  contact?: string[];
  termsOfServiceAgreed?: boolean;
  orders: URL;
  key: JsonWebKey;
}

export interface ICreateAccount {
  contact?: string[];
  termsOfServiceAgreed?: boolean;
  onlyReturnExisting?: boolean;
  externalAccountBinding?: IToken;
}

export interface IUpdateAccount {
  contact: string[];
}

export interface IKeyChange {
  account: string;
  oldKey: JsonWebKey;
}
