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
import { XmlObject } from "./types.ts";
import extractSpkiFromX509 from "./extractSpkiFromX509.ts";
import reorderAttributes from "./reorderAttributes.ts";

function chooseSignAlg(signatureNode: XmlObject): string {
  const alg =
    (((signatureNode.SignedInfo as XmlObject).SignatureMethod as XmlObject)
      ._attributes as XmlObject).Algorithm as string;
  if (
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" == alg ||
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1" == alg
  ) {
    return "RSASSA-PKCS1-v1_5";
  } else {
    throw new Error(`Unsupported sinature algorithm, value: [${alg}]`);
  }
}

function chooseHashAlg(signatureNode: XmlObject): string {
  const dig =
    (((((signatureNode.SignedInfo as XmlObject)
      .Reference as XmlObject) as XmlObject).DigestMethod as XmlObject)
      ._attributes as XmlObject).Algorithm as string;
  if ("http://www.w3.org/2001/04/xmlenc#sha256" == dig) {
    return "SHA-256";
  } else if ("http://www.w3.org/2000/09/xmldsig#sha1" == dig) {
    return "SHA-1";
  } else {
    throw new Error(`Unsupported digest algorithm, value: [${dig}]`);
  }
}

export default async (response: XmlObject): Promise<boolean> => {
  const signatureNode =
    ((response["samlp:Response"] as XmlObject).Assertion as XmlObject)
      .Signature as XmlObject;
  const signAlg = chooseSignAlg(signatureNode);
  const hashAlg = chooseHashAlg(signatureNode);
  const certPem = (((signatureNode.KeyInfo as XmlObject).X509Data as XmlObject)
    .X509Certificate as XmlObject)._text as string;
  const pubKeyPem = extractSpkiFromX509(certPem);
  const pubKeyDer = base64.decode(pubKeyPem);
  const pubKey = await crypto.subtle.importKey(
    "spki",
    pubKeyDer.buffer,
    {
      name: signAlg,
      hash: hashAlg,
    },
    true,
    ["verify"],
  );

  const resp = JSON.parse(JSON.stringify(response));
  const assertion = {
    Assertion: resp["samlp:Response"].Assertion,
  };
  delete assertion.Assertion.Signature;
  reorderAttributes(assertion.Assertion);
  const assertionCanonical = js2xml(assertion, {
    compact: true,
    fullTagEmptyElement: true,
  });
  const assertionCanonicalBytes = encoder.encode(assertionCanonical);
  const sha256Bytes = await crypto.subtle.digest(
    hashAlg,
    assertionCanonicalBytes.buffer,
  );
  const assertionDigest = base64.encode(sha256Bytes);
  const sigInfo = signatureNode.SignedInfo as XmlObject;
  const assertionDigestExpected = ((sigInfo.Reference as XmlObject).DigestValue as XmlObject)
    ._text as string;
  if (assertionDigest != assertionDigestExpected) {
    throw new Error(
      `Digest comparison failure, expected: [${assertionDigestExpected}], actual: [${assertionDigest}]`,
    );
  }
  const si = {
    SignedInfo: sigInfo,
  };
  si.SignedInfo._attributes = {
    xmlns: "http://www.w3.org/2000/09/xmldsig#",
  } as XmlObject;

  const siXml = js2xml(si, {
    compact: true,
    fullTagEmptyElement: true,
  });
  const siXmlBytes = encoder.encode(siXml);
  const sigText = (signatureNode.SignatureValue as XmlObject)._text as string;
  const sigBytes = base64.decode(sigText);
  return await crypto.subtle.verify(
    signAlg,
    pubKey,
    sigBytes.buffer,
    siXmlBytes.buffer,
  );
};
