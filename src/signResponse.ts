/*
 * Copyright 2022, alex at staticlibs.net
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { base64, js2xml } from "./deps.ts";
import { encoder } from "./common.ts";
import { SignOptions, XmlObject } from "./types.ts";
import reorderAttributes from "./reorderAttributes.ts";
import unheaderPem from "./unheaderPem.ts";

function chooseDigestMethod(hashAlg: string): string {
  if ("SHA-1" == hashAlg) {
    return "http://www.w3.org/2000/09/xmldsig#sha1";
  } else if ("SHA-256" == hashAlg) {
    return "http://www.w3.org/2001/04/xmlenc#sha256";
  } else throw new Error(`Cannot determine digest method, hash: [${hashAlg}]`);
}

function choseSignMethod(hashAlg: string): string {
  if ("SHA-1" == hashAlg) {
    return "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
  } else if ("SHA-256" == hashAlg) {
    return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  } else {
    throw new Error(`Cannot determine signature method, hash: [${hashAlg}]`);
  }
}

async function computeDigest(
  respIn: XmlObject,
  hashAlg: string,
): Promise<string> {
  const assertion = {
    Assertion: JSON.parse(JSON.stringify(respIn.Assertion)),
  };
  reorderAttributes(assertion.Assertion);
  const assertionXml = js2xml(assertion, {
    compact: true,
    fullTagEmptyElement: true,
  });
  const assertionBytes = encoder.encode(assertionXml);
  const assertionDigestBytes = await crypto.subtle.digest(
    hashAlg,
    assertionBytes.buffer,
  );
  return base64.encode(assertionDigestBytes);
}

async function loadKey(
  options: SignOptions,
  hashAlg: string,
): Promise<CryptoKey> {
  const keyPem = unheaderPem(options.privateKeyPkcs8Pem);
  const keyDer = base64.decode(keyPem);
  return await crypto.subtle.importKey(
    "pkcs8",
    keyDer.buffer,
    {
      name: options.privateKeyAlgoritmName ?? "RSASSA-PKCS1-v1_5",
      hash: hashAlg,
    },
    true,
    ["sign"],
  );
}

function createSigInfo(
  respIn: XmlObject,
  digestMethod: string,
  sigMethod: string,
  assertionDigest: string,
): XmlObject {
  return {
    SignedInfo: {
      _attributes: {
        "xmlns": "http://www.w3.org/2000/09/xmldsig#",
      },
      CanonicalizationMethod: {
        _attributes: {
          Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        },
      },
      SignatureMethod: {
        _attributes: {
          Algorithm: sigMethod,
        },
      },
      Reference: {
        _attributes: {
          URI: `#${
            ((respIn.Assertion as XmlObject)._attributes as XmlObject).ID
          }`,
        },
        Transforms: {
          Transform: [
            {
              _attributes: {
                Algorithm:
                  "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
              },
            },
            {
              _attributes: {
                Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
              },
            },
          ],
        },
        DigestMethod: {
          "_attributes": {
            Algorithm: digestMethod,
          },
        },
        DigestValue: {
          _text: assertionDigest,
        },
      },
    },
  };
}

async function computeSignature(
  key: CryptoKey,
  sigInfo: XmlObject
): Promise<string> {
  const sigInfoXml = js2xml(sigInfo, {
    compact: true,
    fullTagEmptyElement: true,
  });
  const sigInfoBytes = encoder.encode(sigInfoXml);
  const signBytes = await crypto.subtle.sign(
    key.algorithm,
    key,
    sigInfoBytes.buffer,
  );
  return base64.encode(signBytes);
}

export default async (options: SignOptions): Promise<XmlObject> => {
  const hashAlg = options.privateKeyHash ?? "SHA-256";
  const digestMethod = chooseDigestMethod(hashAlg);
  const sigMethod = choseSignMethod(hashAlg);
  const respIn = options.response["samlp:Response"] as XmlObject;
  const assertionDigest = await computeDigest(respIn, hashAlg);
  const key = await loadKey(options, hashAlg);
  const sigInfo = createSigInfo(
    respIn,
    digestMethod,
    sigMethod,
    assertionDigest,
  );
  const sign = await computeSignature(key, sigInfo);
  const respOut = JSON.parse(JSON.stringify(respIn));
  const sigAttrs = (sigInfo.SignedInfo as XmlObject)._attributes;
  delete (sigInfo.SignedInfo as XmlObject)._attributes;
  respOut.Assertion.Signature = {
    _attributes: sigAttrs,
    SignedInfo: sigInfo.SignedInfo,
    SignatureValue: {
      _text: sign,
    },
    KeyInfo: {
      X509Data: {
        X509Certificate: {
          _text: unheaderPem(options.certificateX509Pem),
        },
      },
    },
  };
  return {
    "samlp:Response": respOut,
  };
};
