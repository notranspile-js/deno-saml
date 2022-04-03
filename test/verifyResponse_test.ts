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

import { path } from "../src/deps.ts";
import createResponse from "../src/createResponse.ts";
import signResponse from "../src/signResponse.ts";
import verifyResponse from "../src/verifyResponse.ts";
import { assert, assertEquals } from "./test_deps.ts";

Deno.test("verifyResponse local", async () => {
  const scriptPath = path.fromFileUrl(import.meta.url);
  const dir = path.dirname(scriptPath);
  const keyPath = path.join(dir, "data", "saml_test_private_key_pkcs8.pem");
  const keyPem = Deno.readTextFileSync(keyPath);
  const certPath = path.join(dir, "data", "saml_test_cert_x509.pem");
  const certPem = Deno.readTextFileSync(certPath);
  const unsigned = createResponse({
    assertionAttributes: {
      foo: "bar",
      baz: "boo",
    },
    audience: "foo",
    destinationUrl: "http://127.0.0.1:8080/acs",
    issuerUrl: "http://127.0.0.1:8000/metadata",
    nameId: "id-foo",
    notAfterMinutes: 42,
    requestId: "id-bar",
    sessionId: "id-baz",
  });
  const signed = await signResponse({
    certificateX509Pem: certPem,
    privateKeyPkcs8Pem: keyPem,
    response: unsigned,
  });
  const verified = await verifyResponse(signed, {});
  assert(verified.success);
  assertEquals(verified.attributes, {
    foo: "bar",
    baz: "boo",
  });
});

Deno.test("verifyResponse AWS", async () => {
  const signed = {
    "_declaration": {
      "_attributes": {
        "version": "1.0",
        "encoding": "UTF-8",
      },
    },
    "saml2p:Response": {
      "_attributes": {
        "xmlns:saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",
        "xmlns:ds": "http://www.w3.org/2000/09/xmldsig#",
        "xmlns:enc": "http://www.w3.org/2001/04/xmlenc#",
        "xmlns:saml2": "urn:oasis:names:tc:SAML:2.0:assertion",
        "Destination": "http://127.0.0.1:8080/acs",
        "ID": "_913d67c5-f394-41c7-aed1-b0b51332763e",
        "IssueInstant": "2022-04-03T12:40:23.344Z",
        "Version": "2.0",
      },
      "saml2:Issuer": {
        "_attributes": {
          "Format": "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
        },
        "_text":
          "https://portal.sso.us-east-1.amazonaws.com/saml/assertion/MDI5NjIzNTA4NDk3X2lucy1kZDJhNTdlN2YyM2EyNzk2",
      },
      "ds:Signature": {
        "ds:SignedInfo": {
          "ds:CanonicalizationMethod": {
            "_attributes": {
              "Algorithm": "http://www.w3.org/2001/10/xml-exc-c14n#",
            },
          },
          "ds:SignatureMethod": {
            "_attributes": {
              "Algorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            },
          },
          "ds:Reference": {
            "_attributes": {
              "URI": "#_913d67c5-f394-41c7-aed1-b0b51332763e",
            },
            "ds:Transforms": {
              "ds:Transform": [
                {
                  "_attributes": {
                    "Algorithm":
                      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                  },
                },
                {
                  "_attributes": {
                    "Algorithm": "http://www.w3.org/2001/10/xml-exc-c14n#",
                  },
                },
              ],
            },
            "ds:DigestMethod": {
              "_attributes": {
                "Algorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
              },
            },
            "ds:DigestValue": {
              "_text": "FOxffcnaoSS52vXXCZQ381fgqEKIOTZ+S2AInwpZx+k=",
            },
          },
        },
        "ds:SignatureValue": {
          "_text":
            "\ndfYveOQnDXoIWNcC4DjHAzKtLowgHpDwv1lL7dks/qa3C34RwN8TG851wIOe9WN40ciy7f5/0jEU\nzByiUTHCaRXVUBaAQsbx63LStoLVlWMrVG8kucDSbZ1jPuQJVIZe50Q099jdrkiNRp+r7pPYLO7K\nKnSeW9YpdOqhAe5jfzF00Klmx8w2bgM0KrhRRF3fgZmWda4VGZPO/6QPxwivwvWzFhveFwRKN359\nnPN5plTHLIQc4BJKJOyXTgpD27jN24BzBLkV0+ldPodP2P3CMJXj835wi2xFo4Nzb1mGI9XSnBLv\noYxI5RvDmqPnqRGvLQTsJ7EUFZQHHkOBKj2veQ==\n",
        },
        "ds:KeyInfo": {
          "ds:X509Data": {
            "ds:X509Certificate": {
              "_text":
                "MIIDAzCCAeugAwIBAgIBATANBgkqhkiG9w0BAQsFADBFMRYwFAYDVQQDDA1hbWF6b25hd3MuY29tMQ0wCwYDVQQLDARJREFTMQ8wDQYDVQQKDAZBbWF6b24xCzAJBgNVBAYTAlVTMB4XDTIyMDMxMDE4MzIzNVoXDTI3MDMxMDE4MzIzNVowRTEWMBQGA1UEAwwNYW1hem9uYXdzLmNvbTENMAsGA1UECwwESURBUzEPMA0GA1UECgwGQW1hem9uMQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMoV2EE8ooZLjeqVhnCJT5QSLeENOLlk/T2rwZpaejFNztkQd0X0X+7UQ33+wlv5AybHXL41ggwAw7b/7j/hHN2TxIjz6RrDgIm60PbvVfT2TuYTCY84fHpnOFKGo/aHCVquwEqPftvyqpJKRTXdLk/YyC6ZhtSYJVKEoGDSs3hm74pf+RkWIEx8/FACu6pk2a9hFbFJOs1f4Zw1RwiKDNFyfHoKrUuebHE+spd+ArhkAU4JDFdK5p5JzqW8SQ8zL7QMiu+tDiwBTBhugPZCgHzIi8m/EaUR3LWzdo2WlN2MyRJ0qusOWN5MfuOQrkkKzxM0zkItnWa6tVGkhGFDah8CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAsqNBZ4+5U6vE45NTwciTdVDqy5MgW0+YbM19VSt4AYT24A1KQ9vD9I0JmH6tzTr4aKQq69yuEvSOwb4Xj5tRNyRN8LH2arb3OxeUKjcRonLHi5T4ypWw+BRrXy6ZN/akNwzugKna3w4ISX8DYiRUZesJpKI+9Z+kCbQy32lIARw8CamPtf12MpNkQWOjklZwXbjvLgDdZAMamW6kvftPphthwBAWjhYqxLKASc+dWaIOGCsATSGtCKTJ3Pv80o9WZ3hbn19M1K8RB9RXMAQsooXw2bzJRuuQ/A39kFV6J02WvsC559sj3IkV1fD5/I06agN7rgGSlga21kAnvk1Ypw==",
            },
          },
        },
      },
      "saml2p:Status": {
        "saml2p:StatusCode": {
          "_attributes": {
            "Value": "urn:oasis:names:tc:SAML:2.0:status:Success",
          },
        },
      },
      "saml2:Assertion": {
        "_attributes": {
          "ID": "_af67f3fd-e242-4264-9b06-7773916df7fd",
          "IssueInstant": "2022-04-03T12:40:23.344Z",
          "Version": "2.0",
        },
        "saml2:Issuer": {
          "_attributes": {
            "Format": "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
          },
          "_text":
            "https://portal.sso.us-east-1.amazonaws.com/saml/assertion/MDI5NjIzNTA4NDk3X2lucy1kZDJhNTdlN2YyM2EyNzk2",
        },
        "ds:Signature": {
          "ds:SignedInfo": {
            "ds:CanonicalizationMethod": {
              "_attributes": {
                "Algorithm": "http://www.w3.org/2001/10/xml-exc-c14n#",
              },
            },
            "ds:SignatureMethod": {
              "_attributes": {
                "Algorithm":
                  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
              },
            },
            "ds:Reference": {
              "_attributes": {
                "URI": "#_af67f3fd-e242-4264-9b06-7773916df7fd",
              },
              "ds:Transforms": {
                "ds:Transform": [
                  {
                    "_attributes": {
                      "Algorithm":
                        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                    },
                  },
                  {
                    "_attributes": {
                      "Algorithm": "http://www.w3.org/2001/10/xml-exc-c14n#",
                    },
                  },
                ],
              },
              "ds:DigestMethod": {
                "_attributes": {
                  "Algorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
                },
              },
              "ds:DigestValue": {
                "_text": "U4RwVCpHk9J1d9kugypLVGJtI+A+y0R//3rFuGPPoIY=",
              },
            },
          },
          "ds:SignatureValue": {
            "_text":
              "\nNvKyak+XlLGStg2VgyCWATAjFylVk6wDWK9Z3HOam2Mbnm9EZSPU6wizXUL6/UmaTcZCNDpAFt9R\nM5O/Fz4cq3cjw5nYebj7OQ96NPCQuOuyYj4wMCjiDNSWCWGvMj7Bqq0CG3ao1VlCFQ/BoRLCQK9+\nSgdL8KL3F3SGQlfvGm75NobQvNU4F78R2tK+1ITbiku4fxrrFbuDDRpTh0dN4jYcqLQ8oMpDQAHt\n3PEEWfW1i3U1DJZkmVgXRD0gvgIxQ/Ro8I0rnyly0mwMbo06yxMgp4vW1ZMk6v71OXPC7ZNkPqay\nQ8xmW0LlDGbP0sxYOQSy3z+wHZp68vn+6qw/Jw==\n",
          },
          "ds:KeyInfo": {
            "ds:X509Data": {
              "ds:X509Certificate": {
                "_text":
                  "MIIDAzCCAeugAwIBAgIBATANBgkqhkiG9w0BAQsFADBFMRYwFAYDVQQDDA1hbWF6b25hd3MuY29tMQ0wCwYDVQQLDARJREFTMQ8wDQYDVQQKDAZBbWF6b24xCzAJBgNVBAYTAlVTMB4XDTIyMDMxMDE4MzIzNVoXDTI3MDMxMDE4MzIzNVowRTEWMBQGA1UEAwwNYW1hem9uYXdzLmNvbTENMAsGA1UECwwESURBUzEPMA0GA1UECgwGQW1hem9uMQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMoV2EE8ooZLjeqVhnCJT5QSLeENOLlk/T2rwZpaejFNztkQd0X0X+7UQ33+wlv5AybHXL41ggwAw7b/7j/hHN2TxIjz6RrDgIm60PbvVfT2TuYTCY84fHpnOFKGo/aHCVquwEqPftvyqpJKRTXdLk/YyC6ZhtSYJVKEoGDSs3hm74pf+RkWIEx8/FACu6pk2a9hFbFJOs1f4Zw1RwiKDNFyfHoKrUuebHE+spd+ArhkAU4JDFdK5p5JzqW8SQ8zL7QMiu+tDiwBTBhugPZCgHzIi8m/EaUR3LWzdo2WlN2MyRJ0qusOWN5MfuOQrkkKzxM0zkItnWa6tVGkhGFDah8CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAsqNBZ4+5U6vE45NTwciTdVDqy5MgW0+YbM19VSt4AYT24A1KQ9vD9I0JmH6tzTr4aKQq69yuEvSOwb4Xj5tRNyRN8LH2arb3OxeUKjcRonLHi5T4ypWw+BRrXy6ZN/akNwzugKna3w4ISX8DYiRUZesJpKI+9Z+kCbQy32lIARw8CamPtf12MpNkQWOjklZwXbjvLgDdZAMamW6kvftPphthwBAWjhYqxLKASc+dWaIOGCsATSGtCKTJ3Pv80o9WZ3hbn19M1K8RB9RXMAQsooXw2bzJRuuQ/A39kFV6J02WvsC559sj3IkV1fD5/I06agN7rgGSlga21kAnvk1Ypw==",
              },
            },
          },
        },
        "saml2:Subject": {
          "saml2:NameID": {
            "_attributes": {
              "Format": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
              "SPNameQualifier": "http://127.0.0.1:8080/metadata",
            },
            "_text": "Username",
          },
          "saml2:SubjectConfirmation": {
            "_attributes": {
              "Method": "urn:oasis:names:tc:SAML:2.0:cm:bearer",
            },
            "saml2:SubjectConfirmationData": {
              "_attributes": {
                "NotOnOrAfter": "2022-04-03T13:40:23.344Z",
                "Recipient": "http://127.0.0.1:8080/acs",
              },
            },
          },
        },
        "saml2:Conditions": {
          "_attributes": {
            "NotBefore": "2022-04-03T12:35:23.344Z",
            "NotOnOrAfter": "2022-04-03T13:40:23.344Z",
          },
          "saml2:AudienceRestriction": {
            "saml2:Audience": {
              "_text": "http://127.0.0.1:8080/metadata",
            },
          },
        },
        "saml2:AuthnStatement": {
          "_attributes": {
            "AuthnInstant": "2022-04-03T12:40:23.344Z",
            "SessionIndex": "_661f58e0-21a2-488b-a1b0-9c41b4c7f69d",
            "SessionNotOnOrAfter": "2022-04-03T13:40:23.344Z",
          },
          "saml2:AuthnContext": {
            "saml2:AuthnContextClassRef": {
              "_text":
                "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
            },
          },
        },
        "saml2:AttributeStatement": {},
      },
    },
  };
  const verified = await verifyResponse(signed, {
    addSigInfoWhitespaces: true,
  });
  assert(verified.success);
  assertEquals(verified.subjectNameId, "Username");
});