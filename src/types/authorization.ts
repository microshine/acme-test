import {IIdentifier} from "./order";

export type AuthorizationStatus = "pending" | "valid" | "invalid" | "deactivated" | "expired" | "revoked";

export type ChallengeStatus = "pending" | "processing" | "valid" | "invalid";

export interface IChallenge {
  type: string;
  status: ChallengeStatus;
  url: string;
  validated?: string;
  error?: object;
}
export interface IHttpChallenge extends IChallenge {
  token: string;
}

export interface IAuthorization {
  identifier: IIdentifier;
  status: AuthorizationStatus;
  expires?: string;
  challenges: IChallenge[];
  wildcard?: boolean;
}
