import {URL} from "./directory";

export interface IAccount {
  status: string;
  contact?: string[];
  termsOfServiceAgreed?: boolean;
  orders: URL;
}
