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
import unheaderPem from "../src/unheaderPem.ts";
import { assert } from "./test_deps.ts";

Deno.test("unheaderPem", () => {
  const scriptPath = path.fromFileUrl(import.meta.url);
  const dir = path.dirname(scriptPath);

  const certPath = path.join(dir, "data", "saml_test_cert_x509.pem");
  const cert = Deno.readTextFileSync(certPath);
  const certPem = unheaderPem(cert);
  assert(certPem.startsWith("MII"));
  assert(certPem.endsWith("=="));

  const keyPath = path.join(dir, "data", "saml_test_key_pkcs8.pem");
  const key = Deno.readTextFileSync(keyPath);
  const keyPem = unheaderPem(key);
  assert(keyPem.startsWith("MII"));
  assert(keyPem.endsWith("Tj"));
});