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

import { base64 } from "../src/deps.ts";
import { XmlObject } from "../src/types.ts";
import parseBase64Message from "../src/parseBase64Message.ts";
import { assert, assertEquals } from "./test_deps.ts";

Deno.test("parseBase64Message", () => {
  const msg = base64.encode('<foo bar="42">baz</foo>');
  const obj = parseBase64Message(msg);
  assert(obj);
  const foo = obj.foo as XmlObject;
  assertEquals((foo._attributes as XmlObject).bar, "42");
  assert(foo._text, "baz");
});