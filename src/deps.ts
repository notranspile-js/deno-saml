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

// sdlib

// @ts-ignore extension
export * as base64 from "https://deno.land/std@0.110.0/encoding/base64.ts";

// @ts-ignore extension
export * as path from "https://deno.land/std@0.110.0/path/mod.ts";

// dayjs
// @ts-ignore extension
import dayjs from "https://deno.land/x/notranspile_dayjs@1.10.7-deno/index.js";
export { dayjs };

// js2xml
// @ts-ignore extension
export { js2xml } from "https://deno.land/x/js2xml@1.0.4/mod.ts";

// xml2js
// @ts-ignore extension
export { xml2js } from "https://deno.land/x/xml2js@1.0.0/mod.ts";