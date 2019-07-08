export type URL = string;

export interface IDirectory {
  newNonce: URL;
  newAccount: URL;
  newOrder: URL;
  newAuthz: URL;
  revokeCert: URL;
  keyChange: URL;
  meta?: {
    termsOfService?: URL;
    website?: URL;
    caaIdentities?: URL[];
    externalAccountRequired?: boolean;
  };
}
