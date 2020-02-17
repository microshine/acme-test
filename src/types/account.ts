import { URL } from "./directory";
import { IToken } from "./token";

export interface IAccount {
  status: "valid" | "deactivated" | "revoked";
  contact?: string[];
  termsOfServiceAgreed?: boolean;
  orders: URL;
  key: JsonWebKey;
  externalAccountBinding: any;
}

export interface ICreateAccountProtocol {
  contact?: string[];
  termsOfServiceAgreed?: boolean;
  onlyReturnExisting?: boolean;
  externalAccountBinding?: IToken;
}

export interface ICreateAccount {
  contact?: string[];
  termsOfServiceAgreed?: boolean;
  onlyReturnExisting?: boolean;
  externalAccountBinding?: IExternalAccountBinding;
}

export interface IExternalAccountBinding {
  challenge: string;
  kid: string;
}

export interface IUpdateAccount {
  contact: string[];
}

export interface IKeyChange {
  account: string;
  oldKey: JsonWebKey;
}
