export type OrderStatus = "pending" | "ready" | "processing" | "valid" | "invalid";

export interface IOrder {
  status: OrderStatus;
  identifiers: IIdentifier[];
  expires?: string;
  notAfter?: string;
  notBefore?: string;
  errors: any;
  authorizations: string[];
  finalize: string;
  certificate?: string;
}

export interface IIdentifier {
  type: string;
  value: string;
}

export interface INewOrder {
  identifiers: IIdentifier[];
  notAfter?: string;
  notBefore?: string;
}
