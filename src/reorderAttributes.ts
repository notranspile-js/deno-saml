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

import { XmlObject } from "./types.ts";

export default (element: XmlObject): void => {
  const attrs = element._attributes as Record<string, string>;
  const keys = Object.keys(attrs);
  keys.sort((a, b) => {
    if (a == "xmlns") {
      return -1;
    }
    if (b == "xmlns") {
      return 1;
    }
    if (a.startsWith("xmlns:") && !b.startsWith("xmlns:")) {
      return -1;
    }
    if (!a.startsWith("xmlns:") && b.startsWith("xmlns:")) {
      return 1;
    }
    if (a.startsWith("xmlns:") && b.startsWith("xmlns:")) {
      return (attrs[a]).localeCompare(attrs[b]);
    }
    return a.localeCompare(b);
  });
  const orderedAttrs = {} as Record<string, unknown>;
  for (const key of keys) {
    orderedAttrs[key] = attrs[key];
  }
  element._attributes = orderedAttrs as XmlObject;
};
