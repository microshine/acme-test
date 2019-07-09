import { IError } from "./types";

export class AcmeError extends Error {

  public status: number;
  public type: string;

  constructor(error: IError) {
    super();
    this.name = "AcmeError";
    this.message = error.detail;
    this.type = error.type;
    this.status = error.status;
  }
}
