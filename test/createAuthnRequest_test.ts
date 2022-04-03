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

import { XmlObject } from "../src/types.ts";
import createAuthnRequest from "../src/createAuthnRequest.ts";
import { assert } from "./test_deps.ts";

Deno.test("createAuthnRequest", () => {
  const obj = createAuthnRequest({
    acsUrl: "http://127.0.0.1:8080/acs",
    destinationUrl: "http://127.0.0.1:8080/sso",
    issuer: "http://127.0.0.1:8080/metadata"
  });
  const req = obj["samlp:AuthnRequest"] as XmlObject;
  assert(req);
  assert(req._attributes);
  assert(req.Issuer);
  assert(req["samlp:NameIDPolicy"]);
});