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

import { dayjs } from "./deps.ts";
import { dateFormat } from "./common.ts";
import { IdPMetadataOptions, XmlObject } from "./types.ts";
import unheaderPem from "./unheaderPem.ts";

export default (options: IdPMetadataOptions): XmlObject => {
  const validUntil = dayjs().add(options.validMinutes, "minute");
  const cert = unheaderPem(options.certificateX509Pem);

  return {
    EntityDescriptor: {
      _attributes: {
        xmlns: "urn:oasis:names:tc:SAML:2.0:metadata",
        "xmlns:ds": "http://www.w3.org/2000/09/xmldsig#",
        ID: options.id,
        entityID: options.entityId,
        validUntil: validUntil.format(dateFormat),
      },
      IDPSSODescriptor: {
        _attributes: {
          protocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
        },
        Extensions: {},
        KeyDescriptor: {
          _attributes: {
            use: "signing",
          },
          "ds:KeyInfo": {
            "ds:X509Data": {
              "ds:X509Certificate": {
                _text: cert,
              },
            },
          },
        },
        SingleSignOnService: {
          _attributes: {
            Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            Location: options.httpPostBindingUrl,
          },
        },
      },
    },
  };
};
