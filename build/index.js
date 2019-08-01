'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

function _interopDefault (ex) { return (ex && (typeof ex === 'object') && 'default' in ex) ? ex['default'] : ex; }

require('colors');
var jws = _interopDefault(require('jws'));
var fetch = _interopDefault(require('node-fetch'));
var pvtsutils = require('pvtsutils');
var core = require('webcrypto-core');
var webcrypto = require('@peculiar/webcrypto');

const urn = "urn:ietf:params:acme:error:";
const errorType = {
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

const crypto = new webcrypto.Crypto();

class AcmeError extends Error {
    constructor(error) {
        super();
        this.name = "AcmeError";
        this.message = error.detail;
        this.type = error.type;
        this.status = error.status;
    }
}

(function (RevocationReason) {
    RevocationReason[RevocationReason["Unspecified"] = 0] = "Unspecified";
    RevocationReason[RevocationReason["KeyCompromise"] = 1] = "KeyCompromise";
    RevocationReason[RevocationReason["CACompromise"] = 2] = "CACompromise";
    RevocationReason[RevocationReason["AffiliationChanged"] = 3] = "AffiliationChanged";
    RevocationReason[RevocationReason["Superseded"] = 4] = "Superseded";
    RevocationReason[RevocationReason["CessationOfOperation"] = 5] = "CessationOfOperation";
    RevocationReason[RevocationReason["CertificateHold"] = 6] = "CertificateHold";
    RevocationReason[RevocationReason["RemoveFromCRL"] = 8] = "RemoveFromCRL";
    RevocationReason[RevocationReason["PrivilegeWithdrawn"] = 9] = "PrivilegeWithdrawn";
    RevocationReason[RevocationReason["AACompromise"] = 10] = "AACompromise";
})(exports.RevocationReason || (exports.RevocationReason = {}));
class AcmeClient {
    constructor(options) {
        this.lastNonce = "";
        this.authKey = {
            key: options.authKey,
        };
        this.debug = !!options.debug;
    }
    async initialize(url) {
        const response = await fetch(url, { method: "GET" });
        this.directory = await response.json();
        return this.directory;
    }
    async nonce() {
        const response = await fetch(this.getDirectory().newNonce, { method: "GET" });
        return this.getNonce(response);
    }
    async createAccount(params) {
        const res = await this.request(this.getDirectory().newAccount, "POST", params, false);
        if (!res.location) {
            throw new Error("Cannot get Location header");
        }
        this.authKey.id = res.location;
        return res;
    }
    async updateAccount(params) {
        return this.request(this.getKeyId(), "POST", params);
    }
    async changeKey(key) {
        const keyChange = {
            account: this.getKeyId(),
            oldKey: await this.exportPublicKey(this.authKey.key),
        };
        const innerToken = await this.createJWS(keyChange, { omitNonce: true, url: this.getDirectory().keyChange, key });
        const res = await this.request(this.getDirectory().keyChange, "POST", innerToken);
        if (key) {
            this.authKey.key = key;
        }
        return res;
    }
    async revoke(certificate, reason) {
        return this.request(this.getDirectory().revokeCert, "POST", {
            certificate: pvtsutils.Convert.ToBase64Url(certificate),
            reason,
        });
    }
    async deactivateAccount() {
        return this.deactivate(this.getKeyId());
    }
    async deactivateAuthorization(url) {
        return this.deactivate(url);
    }
    async deactivate(url) {
        return this.request(url, "POST", { status: "deactivated" });
    }
    async request(url, method = "GET", params, kid = true) {
        try {
            const res = await this.requestACME(url, method, params, kid);
            return res;
        }
        catch (error) {
            if (error.type === errorType.badNonce) {
                try {
                    const res = await this.requestACME(url, method, params, kid);
                    return res;
                }
                catch (err) {
                    error = err;
                }
            }
            throw new AcmeError(error);
        }
    }
    async requestACME(url, method = "GET", params, kid = true) {
        let response;
        if (!this.lastNonce) {
            this.lastNonce = await this.nonce();
        }
        if (!params || method === "GET") {
            params = "";
        }
        const token = kid
            ? await this.createJWS(params, Object.assign({ url }, { kid: this.getKeyId() }))
            : await this.createJWS(params, Object.assign({ url }));
        response = await fetch(url, {
            method: "POST",
            headers: {
                "content-type": "application/jose+json",
            },
            body: JSON.stringify(token),
        });
        this.lastNonce = response.headers.get("replay-nonce") || "";
        const headers = {
            link: response.headers.get("link") || undefined,
            location: response.headers.get("location") || undefined,
        };
        if (!(response.status >= 200 && response.status < 300)) {
            const error = await response.text();
            let errJson;
            try {
                errJson = JSON.parse(error);
                this.logResponse(url, errJson, method);
            }
            catch {
                throw new Error(error);
            }
            throw new AcmeError(errJson);
        }
        let result;
        const contentType = response.headers.get("content-type");
        if (contentType && contentType.includes("application/pem-certificate-chain")) {
            result = await response.text();
        }
        else if (contentType) {
            result = await response.json();
        }
        const res = {
            status: response.status,
            ...headers,
            result,
        };
        this.logResponse(url, res, method);
        return res;
    }
    async newOrder(params) {
        return this.request(this.getDirectory().newOrder, "POST", params);
    }
    async getChallenge(url, method = "GET") {
        const res = await this.request(url, method, {});
        if (method === "POST") {
            await this.pause(2000);
        }
        return res;
    }
    async finalize(url, params) {
        return this.request(url, "POST", params);
    }
    async getAuthorization(url, method = "GET") {
        return this.request(url, method);
    }
    async getCertificate(url, method = "POST") {
        const response = await this.request(url, method);
        const certs = [];
        const regex = /(-----BEGIN CERTIFICATE-----[a-z0-9\/+=\n]+-----END CERTIFICATE-----)/gmis;
        let matches = null;
        while (matches = regex.exec(response.result)) {
            certs.push(matches[1]);
        }
        const res = {
            link: response.link,
            location: response.location,
            result: certs,
            status: response.status,
        };
        return res;
    }
    async createJWS(payload, options) {
        const key = options.key || this.authKey.key;
        const keyPem = key.algorithm.name === "HMAC"
            ? Buffer.from(await crypto.subtle.exportKey("raw", key))
            : await this.getKeyPem(key);
        const header = {
            alg: (key.algorithm.name === "ECDSA"
                ? `ES${key.algorithm.namedCurve.replace("P-", "")}`
                : key.algorithm.name === "HMAC"
                    ? "HS256"
                    : "RS256"),
        };
        if (!options.kid) {
            const jwk = await this.exportPublicKey(key);
            header.jwk = jwk;
        }
        else {
            header.kid = options.kid;
        }
        if (options.url) {
            header.url = options.url;
        }
        if (!options.omitNonce) {
            header.nonce = this.lastNonce;
        }
        const signature = jws.sign({
            header,
            privateKey: keyPem,
            payload,
        });
        const parts = signature.split(".");
        const res = {
            protected: parts[0],
            payload: parts[1],
            signature: parts[2],
        };
        return res;
    }
    getKeyId() {
        if (!this.authKey.id) {
            throw new Error("Create or Find account first");
        }
        return this.authKey.id;
    }
    async exportPublicKey(key) {
        key = key || this.authKey.key;
        let jwk = await crypto.subtle.exportKey("jwk", key);
        delete jwk.d;
        const publicKey = await crypto.subtle.importKey("jwk", jwk, key.algorithm, true, ["verify"]);
        jwk = await crypto.subtle.exportKey("jwk", publicKey);
        return jwk;
    }
    async getKeyPem(key) {
        const pkcs8 = await crypto.subtle.exportKey("pkcs8", key);
        return core.PemConverter.fromBufferSource(pkcs8, "PRIVATE KEY");
    }
    getDirectory() {
        if (!this.directory) {
            throw new Error("Call 'initialize' method fist");
        }
        return this.directory;
    }
    getNonce(response) {
        const res = response.headers.get("replay-nonce");
        if (!res) {
            throw new Error("Cannot get replay-nonce header");
        }
        return res;
    }
    async pause(ms) {
        return new Promise((resolve) => setTimeout(resolve, ms));
    }
    logResponse(url, res, method) {
        if (this.debug) {
            console.log(`${method} RESPONSE ${url}`.blue);
            console.log("Result", res);
        }
    }
}

exports.AcmeClient = AcmeClient;
