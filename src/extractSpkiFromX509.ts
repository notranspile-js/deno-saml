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

import { base64 } from "./deps.ts";
import unheaderPem from "./unheaderPem.ts";

function checkOctet(der: Uint8Array, idx: number, expected: number) {
  const octet = der[idx];
  if (octet != expected) {
    throw new Error(
      `Error extracting public key, idx: [${idx}], octet: [${
        octet.toString(16)
      }], expected: [${expected.toString(16)}]`,
    );
  }
}

// https://en.wikipedia.org/wiki/X.509#Structure_of_a_certificate
// openssl asn1parse -in cert.der -inform der -i
function extractPubKey(der: Uint8Array) {
  // SEQUENCE
  checkOctet(der, 0, 0x30);
  checkOctet(der, 1, 0x82);
  // SEQUENCE
  checkOctet(der, 4, 0x30);
  checkOctet(der, 5, 0x82);
  // cont [ 0 ]
  // INTEGER
  const versionStart = 8;
  checkOctet(der, versionStart, 0xa0);
  const versionLen = 2 + der[versionStart + 1];
  // INTEGER
  const serialNumStart = versionStart + versionLen;
  checkOctet(der, serialNumStart, 0x02);
  const serialNumLen = 2 + der[serialNumStart + 1];
  // SEQUENCE
  const sigAlgIdStart = serialNumStart + serialNumLen;
  checkOctet(der, sigAlgIdStart, 0x30);
  const sigAlgIdLen = 2 + der[sigAlgIdStart + 1];
  // SEQUENCE
  const issuerNameStart = sigAlgIdStart + sigAlgIdLen;
  checkOctet(der, issuerNameStart, 0x30);
  const issuerNameLen = 2 + der[issuerNameStart + 1];
  // SEQUENCE
  const validityPeriodStart = issuerNameStart + issuerNameLen;
  checkOctet(der, validityPeriodStart, 0x30);
  const validityPeriodLen = 2 + der[validityPeriodStart + 1];
  // SEQUENCE
  const subjectNameStart = validityPeriodStart + validityPeriodLen;
  checkOctet(der, subjectNameStart, 0x30);
  let subjectNameLen = -1;
  if (0x81 == der[subjectNameStart + 1]) {
    subjectNameLen = 3 + der[subjectNameStart + 2];
  } else {
    subjectNameLen = 2 + der[subjectNameStart + 1];
  }
  // SEQUENCE
  const publicKeyStart = subjectNameStart + subjectNameLen;
  checkOctet(der, publicKeyStart, 0x30);
  checkOctet(der, publicKeyStart + 1, 0x82);
  const publicKeyLen = 4 + (der[publicKeyStart + 2] * 256) +
    der[publicKeyStart + 3];

  const view = new Uint8Array(der.buffer, publicKeyStart, publicKeyLen);
  return new Uint8Array(view);
}

export default (certX509Pem: string): string => {
  const pemUnheadered = unheaderPem(certX509Pem);
  const x509Der = base64.decode(pemUnheadered);
  const spkiDer = extractPubKey(x509Der);
  return base64.encode(spkiDer);
};
