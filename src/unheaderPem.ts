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

const x509Header = "-----BEGIN CERTIFICATE-----";
const x509Footer = "-----END CERTIFICATE-----";
const pkcs8Header = "-----BEGIN PRIVATE KEY-----";
const pkcs8Footer = "-----END PRIVATE KEY-----";
const spkiHeader = "-----BEGIN PUBLIC KEY-----";
const spkiFooter = "-----END PUBLIC KEY-----";

export default (pem: string): string => {
  let header = null;
  let footer = null;
  const headered = pem.trim();
  if (headered.startsWith(x509Header) && headered.endsWith(x509Footer)) {
    header = x509Header;
    footer = x509Footer;
  } else if (headered.startsWith(pkcs8Header) && headered.endsWith(pkcs8Footer)) {
    header = pkcs8Header;
    footer = pkcs8Footer;
  } else if (headered.startsWith(spkiHeader) && headered.endsWith(spkiFooter)) {
    header = spkiHeader;
    footer = spkiFooter;
  } else {
    return pem;
  }
  const unheadered = headered.substring(
    header.length,
    headered.length - footer.length,
  ).trim();
  return unheadered.replaceAll(/\s/g, "");
};
