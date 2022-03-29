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
import { assert } from "./test_deps.ts";

Deno.test("verifyResponse", async () => {
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
    response: unsigned
  });
  const verified = await verifyResponse(signed);
  assert(verified);
});