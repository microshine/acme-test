import { Base64UrlString } from "./types";

export interface IToken {
  protected: Base64UrlString;
  payload: Base64UrlString;
  signature: Base64UrlString;
}
