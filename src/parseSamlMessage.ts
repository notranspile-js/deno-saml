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

import { base64, xml2js } from "./deps.ts";
import { decoder } from "./common.ts";
import { XmlObject } from "./types.ts";

export default (messageBase64: string) : XmlObject => {
  const bin = base64.decode(messageBase64);
  const xml = decoder.decode(bin);
  return xml2js(xml, {
    compact: true
  }) as XmlObject;
}