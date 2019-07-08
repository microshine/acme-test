import {URL} from "./directory";

export interface IAccount {
  status: "valid" | "deactivated" | "revoked";
  contact?: string[];
  termsOfServiceAgreed?: boolean;
  orders: URL;
}
