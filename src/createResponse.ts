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
import { ResponseOptions, XmlObject } from "./types.ts";

export default (options: ResponseOptions): XmlObject => {
  const now = dayjs().utc();
  const notAfter = now.add(options.notAfterMinutes, "minute");

  const attrs = [];
  for (const [name, val] of Object.entries(options.assertionAttributes)) {
    attrs.push({
      _attributes: {
        Name: name,
      },
      AttributeValue: {
        _text: val,
      },
    });
  }

  return {
    "samlp:Response": {
      _attributes: {
        "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        Destination: options.destinationUrl,
        ID: `id-${crypto.randomUUID()}`,
        InResponseTo: options.requestId,
        IssueInstant: now.format(dateFormat),
        Version: "2.0",
      },
      Issuer: {
        _attributes: {
          xmlns: "urn:oasis:names:tc:SAML:2.0:assertion",
        },
        _text: options.issuerUrl,
      },
      "samlp:Status": {
        "samlp:StatusCode": {
          _attributes: {
            Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
          },
        },
      },
      Assertion: {
        _attributes: {
          xmlns: "urn:oasis:names:tc:SAML:2.0:assertion",
          ID: `id-${crypto.randomUUID()}`,
          IssueInstant: now.format(dateFormat),
          Version: "2.0",
        },
        Issuer: {
          _text: options.issuerUrl,
        },
        Subject: {
          NameID: {
            _attributes: {
              Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
            },
            _text: options.nameId,
          },
          SubjectConfirmation: {
            _attributes: {
              Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
            },
            SubjectConfirmationData: {
              _attributes: {
                InResponseTo: options.requestId,
                NotOnOrAfter: notAfter.format(dateFormat),
                Recipient: options.destinationUrl,
              },
            },
          },
        },
        Conditions: {
          _attributes: {
            NotBefore: now.format(dateFormat),
            NotOnOrAfter: notAfter.format(dateFormat),
          },
          AudienceRestriction: {
            Audience: {
              "_text": options.audience,
            },
          },
        },
        AttributeStatement: {
          Attribute: attrs,
        },
        AuthnStatement: {
          _attributes: {
            AuthnInstant: now.format(dateFormat),
            SessionIndex: options.sessionId,
          },
          AuthnContext: {
            AuthnContextClassRef: {
              _text: "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
            },
          },
        },
      },
    },
  };
};
