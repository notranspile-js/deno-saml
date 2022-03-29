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
import reorderAttributes from "../src/reorderAttributes.ts";
import { assertEquals } from "./test_deps.ts";

Deno.test("reorderAttributes", () => {
  const el = {
    _attributes: {
      foo: "42",
      bar: "41",
      xmlns: "43",
      "xmlns:a": "45",
      "xmlns:b": "44",
    },
  } as XmlObject;
  reorderAttributes(el);
  assertEquals(Object.keys(el._attributes), [
    "xmlns",
    "xmlns:b",
    "xmlns:a",
    "bar",
    "foo",
  ]);
});
