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

function parseLength(bytes: Uint8Array, offset = 0) {
  // Get the initial length byte
  const firstByte = bytes[offset];
  
  // Short form length
  if (firstByte < 0x80) {
    return {
      length: firstByte,
      lengthBytes: 1,
      totalLength: firstByte + 1 // Includes the first length byte itself
    };
  }
  
  // Long form length
  const numLengthBytes = firstByte & 0x7F; // Mask off the MSB to get the count of length bytes
  let length = 0;
  
  for (let i = 1; i <= numLengthBytes; i++) {
    length = (length << 8) | bytes[offset + i]; // Combine bytes to form the length
  }
  
  return {
    length,
    lengthBytes: numLengthBytes + 1, // Includes the first length byte itself
    totalLength: length + numLengthBytes + 1
  };
}

// https://en.wikipedia.org/wiki/X.509#Structure_of_a_certificate
// openssl asn1parse -in cert.der -inform der -i
function extractPubKey(der: Uint8Array) {
  let pos = 0;
  // SEQUENCE
  checkOctet(der, 0, 0x30);
  pos += 1;
  const seq1Len = parseLength(der, pos);
  pos += seq1Len.lengthBytes;
  // SEQUENCE
  checkOctet(der, 4, 0x30);
  pos += 1;
  const seq2Len = parseLength(der, pos);
  pos += seq2Len.lengthBytes;
  // cont [ 0 ]
  checkOctet(der, pos, 0xa0);
  pos += 1;
  const versionLen = parseLength(der, pos);
  pos += versionLen.totalLength;
  // INTEGER
  checkOctet(der, pos, 0x02);
  pos += 1;
  const serialNumLen = parseLength(der, pos);
  pos += serialNumLen.totalLength;
  // SEQUENCE
  const sigAlgIdStart = pos;
  checkOctet(der, sigAlgIdStart, 0x30);
  pos += 1;
  const sigAlgIdLen = parseLength(der, pos);
  pos += sigAlgIdLen.totalLength;
  // SEQUENCE
  checkOctet(der, pos, 0x30);
  pos += 1;
  const issuerNameLen = parseLength(der, pos);
  pos += issuerNameLen.totalLength;
  // SEQUENCE
  checkOctet(der, pos, 0x30);
  pos += 1;
  const validityPeriodLen = parseLength(der, pos);
  pos += validityPeriodLen.totalLength;
  // SEQUENCE
  checkOctet(der, pos, 0x30);
  pos += 1;
  const subjectNameLen = parseLength(der, pos);
  pos += subjectNameLen.totalLength;
  // SEQUENCE
  const publicKeyStart = pos;
  checkOctet(der, pos, 0x30);
  pos += 1;
  const publicKeyLen = parseLength(der, pos);
  const publicKeyFullLenNum = publicKeyLen.totalLength + 1;
  const view = new Uint8Array(der.buffer, publicKeyStart, publicKeyFullLenNum);
  return new Uint8Array(view);
}

export default (certX509Pem: string): string => {
  const pemUnheadered = unheaderPem(certX509Pem);
  const x509Der = base64.decode(pemUnheadered);
  const spkiDer = extractPubKey(x509Der);
  return base64.encode(spkiDer);
};
