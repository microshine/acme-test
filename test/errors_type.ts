const urn = "urn:ietf:params:acme:error:";

export const errorType = {
 malformed: `${urn}malformed`,
 badNonce: `${urn}badNonce`,
 accountDoesNotExist: `${urn}accountDoesNotExist`,
 unsupportedContact: `${urn}unsupportedContact`,
 invalidContact: `${urn}invalidContact`,
 incorrectResponse: `${urn}incorrectResponse`,
 unauthorized: `${urn}unauthorized`,
 badSignatureAlgorithm: `${urn}badSignatureAlgorithm`,
 badPublicKey: `${urn}badPublicKey`,
 badRevocationReason: `${urn}badRevocationReason`,
 alreadyRevoked: `${urn}alreadyRevoked`,
};
