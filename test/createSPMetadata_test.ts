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
import createSPMetadata from "../src/createSPMetadata.ts";
import { assert } from "./test_deps.ts";

Deno.test("createSPMetadata", () => {
  const obj = createSPMetadata({
    acsUrl: "http://127.0.0.1:8080/acs",
    metadataUrl: "http://127.0.0.1:8080/metadata",
    validMinutes: 42,
  });
  const desc = obj.EntityDescriptor as XmlObject;
  assert(desc);
  assert(desc._attributes);
  assert(desc.SPSSODescriptor);
});
