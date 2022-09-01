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

import { base64, dayjs, js2xml } from "./deps.ts";
import { dateFormat, encoder } from "./common.ts";
import {
  VerifyOptions,
  VerifyPeriod,
  VerifyResult,
  XmlObject,
} from "./types.ts";
import extractSpkiFromX509 from "./extractSpkiFromX509.ts";
import reorderAttributes from "./reorderAttributes.ts";

function chooseSignAlg(
  nm: Record<string, string>,
  signatureNode: XmlObject,
): string {
  const alg = (((signatureNode[`${nm.dsig}SignedInfo`] as XmlObject)[
    `${nm.dsig}SignatureMethod`
  ] as XmlObject)
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

function chooseHashAlg(
  nm: Record<string, string>,
  signatureNode: XmlObject,
): string {
  const dig = (((((signatureNode[`${nm.dsig}SignedInfo`] as XmlObject)[
    `${nm.dsig}Reference`
  ] as XmlObject) as XmlObject)[`${nm.dsig}DigestMethod`] as XmlObject)
    ._attributes as XmlObject).Algorithm as string;
  if ("http://www.w3.org/2001/04/xmlenc#sha256" == dig) {
    return "SHA-256";
  } else if ("http://www.w3.org/2000/09/xmldsig#sha1" == dig) {
    return "SHA-1";
  } else {
    throw new Error(`Unsupported digest algorithm, value: [${dig}]`);
  }
}

function namespacesMap(response: XmlObject): Record<string, string> {
  const nsSaml = "urn:oasis:names:tc:SAML:2.0:protocol";
  const nsAssert = "urn:oasis:names:tc:SAML:2.0:assertion";
  const nsDsig = "http://www.w3.org/2000/09/xmldsig#";
  let idx = 0;
  if (response._declaration) {
    idx = 1;
  }
  const respNode = Object.entries(response)[idx][1] as Record<string, unknown>;
  const respAttrs = respNode._attributes as Record<string, string>;
  let samlPrefix = "";
  let assertPrefix = "";
  let dsigPrefix = "";
  const nsPrefLen = "xmlns".length + 1;
  for (const [name, val] of Object.entries(respAttrs)) {
    if (nsSaml == val) {
      samlPrefix = `${name.substring(nsPrefLen)}:`;
    } else if (nsAssert == val) {
      assertPrefix = `${name.substring(nsPrefLen)}:`;
    } else if (nsDsig == val) {
      dsigPrefix = `${name.substring(nsPrefLen)}:`;
    }
  }
  return {
    saml: samlPrefix,
    assertns: assertPrefix,
    dsig: dsigPrefix,
  };
}

function addWhitespaces(
  nm: Record<string, string>,
  xml: string,
): string {
  const ns = nm.dsig;
  let res = xml;
  res = res.replace(
    `<${ns}CanonicalizationMethod`,
    `\n<${ns}CanonicalizationMethod`,
  );
  res = res.replace(`<${ns}SignatureMethod`, `\n<${ns}SignatureMethod`);
  res = res.replace(`<${ns}Reference`, `\n<${ns}Reference`);
  res = res.replace(`<${ns}Transforms>`, `\n<${ns}Transforms>`);
  res = res.replaceAll(
    `<${ns}Transform Algorithm=`,
    `\n<${ns}Transform Algorithm=`,
  );
  res = res.replace(`</${ns}Transforms>`, `\n</${ns}Transforms>`);
  res = res.replace(`<${ns}DigestMethod`, `\n<${ns}DigestMethod`);
  res = res.replace(`<${ns}DigestValue>`, `\n<${ns}DigestValue>`);
  res = res.replace(`</${ns}Reference>`, `\n</${ns}Reference>`);
  res = res.replace(`</${ns}SignedInfo>`, `\n</${ns}SignedInfo>`);
  return res;
}

function extractNameId(
  nm: Record<string, string>,
  response: XmlObject,
): string {
  return ((((response[`${nm.saml}Response`] as XmlObject)[
    `${nm.assertns}Assertion`
  ] as XmlObject)[`${nm.assertns}Subject`] as XmlObject)[
    `${nm.assertns}NameID`
  ] as XmlObject)._text as string;
}

function extractAttributes(
  nm: Record<string, string>,
  response: XmlObject,
): Record<string, string> {
  let attrs = (((response[`${nm.saml}Response`] as XmlObject)[
    `${nm.assertns}Assertion`
  ] as XmlObject)[`${nm.assertns}AttributeStatement`] as XmlObject)[
    `${nm.assertns}Attribute`
  ] as XmlObject[];
  if (!attrs) {
    return {};
  }
  if (!(attrs instanceof Array)) {
    attrs = [attrs];
  }
  const res = {} as Record<string, string>;
  for (const at of attrs) {
    const name = (at._attributes as XmlObject).Name as string;
    const val = (at[`${nm.assertns}AttributeValue`] as XmlObject)
      ._text as string;
    res[name] = val;
  }
  return res;
}

function extractPeriod(
  nm: Record<string, string>,
  response: XmlObject,
): VerifyPeriod {
  const attrs = (((response[`${nm.saml}Response`] as XmlObject)[
    `${nm.assertns}Assertion`
  ] as XmlObject)[`${nm.assertns}Conditions`] as XmlObject)
    ._attributes as Record<string, string>;

  return {
    from: dayjs(attrs.NotBefore, dateFormat).format(),
    to: dayjs(attrs.NotOnOrAfter, dateFormat).format()
  };
}

export default async (
  response: XmlObject,
  options: VerifyOptions,
): Promise<VerifyResult> => {
  const nm = namespacesMap(response);
  const signatureNode = ((response[`${nm.saml}Response`] as XmlObject)[
    `${nm.assertns}Assertion`
  ] as XmlObject)[`${nm.dsig}Signature`] as XmlObject;
  const signAlg = chooseSignAlg(nm, signatureNode);
  const hashAlg = chooseHashAlg(nm, signatureNode);
  const certPem = (((signatureNode[`${nm.dsig}KeyInfo`] as XmlObject)[
    `${nm.dsig}X509Data`
  ] as XmlObject)[`${nm.dsig}X509Certificate`] as XmlObject)._text as string;
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
  const assertion = {} as XmlObject;
  assertion[`${nm.assertns}Assertion`] =
    resp[`${nm.saml}Response`][`${nm.assertns}Assertion`],
    delete (assertion[`${nm.assertns}Assertion`] as XmlObject)[
      `${nm.dsig}Signature`
    ];
  if ("" != nm.assertns) {
    (((assertion[`${nm.assertns}Assertion`] as XmlObject)
      ._attributes) as XmlObject)[
        `xmlns:${nm.assertns.substring(0, nm.assertns.length - 1)}`
      ] = "urn:oasis:names:tc:SAML:2.0:assertion";
  }
  reorderAttributes(assertion[`${nm.assertns}Assertion`] as XmlObject);
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
  const sigInfo = signatureNode[`${nm.dsig}SignedInfo`] as XmlObject;
  const assertionDigestExpected =
    ((sigInfo[`${nm.dsig}Reference`] as XmlObject)[
      `${nm.dsig}DigestValue`
    ] as XmlObject)
      ._text as string;
  if (assertionDigest != assertionDigestExpected) {
    throw new Error(
      `Digest comparison failure, expected: [${assertionDigestExpected}], actual: [${assertionDigest}]`,
    );
  }
  const si = {} as XmlObject;
  si[`${nm.dsig}SignedInfo`] = sigInfo;
  if ("" == nm.dsig) {
    (si.SignedInfo as XmlObject)._attributes = {
      xmlns: "http://www.w3.org/2000/09/xmldsig#",
    } as XmlObject;
  } else {
    const sattrs = {} as XmlObject;
    sattrs[`xmlns:${nm.dsig.substring(0, nm.dsig.length - 1)}`] =
      "http://www.w3.org/2000/09/xmldsig#";
    (si[`${nm.dsig}SignedInfo`] as XmlObject)._attributes = sattrs;
  }

  let siXml = js2xml(si, {
    compact: true,
    fullTagEmptyElement: true,
  });
  if (true == options.addSigInfoWhitespaces) {
    siXml = addWhitespaces(nm, siXml);
  }
  const siXmlBytes = encoder.encode(siXml);
  const sigText = (signatureNode[`${nm.dsig}SignatureValue`] as XmlObject)
    ._text as string;
  const sigTextFlat = sigText.replaceAll(/\s/g, "");
  const sigBytes = base64.decode(sigTextFlat);
  const verified = await crypto.subtle.verify(
    signAlg,
    pubKey,
    sigBytes.buffer,
    siXmlBytes.buffer,
  );
  return {
    success: verified,
    subjectNameId: extractNameId(nm, response),
    certificateX509Pem: certPem,
    period: extractPeriod(nm, response),
    attributes: extractAttributes(nm, response),
  };
};
