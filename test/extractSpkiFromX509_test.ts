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

import { base64, path } from "../src/deps.ts";
import extractSpkiFromX509 from "../src/extractSpkiFromX509.ts";
import { assert } from "./test_deps.ts";

Deno.test("extractSpkiFromX509", async () => {
  const scriptPath = path.fromFileUrl(import.meta.url);
  const dir = path.dirname(scriptPath);
  const certPath = path.join(dir, "data", "saml_test_cert_x509.pem");
  const cert = Deno.readTextFileSync(certPath);
  const pem = extractSpkiFromX509(cert);
  const der = base64.decode(pem);
  const key = await crypto.subtle.importKey(
    "spki",
    der.buffer,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    true,
    ["verify"],
  );
  assert(key);
});