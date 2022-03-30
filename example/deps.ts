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

// stdlib

// @ts-ignore extension
export * as io from "https://deno.land/std@0.110.0/io/mod.ts";

// @ts-ignore extension
export * as path from "https://deno.land/std@0.110.0/path/mod.ts";

// simple_server
// @ts-ignore extension
export {
  SimpleRequest,
  SimpleServer,
} from "https://deno.land/x/simple_server@1.1.0/mod.ts";
export type { SimpleResponse } from "https://deno.land/x/simple_server@1.1.0/mod.ts";

// saml
// @ts-ignore extension
export * as saml from "../src/mod.ts";