
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

import { mustache } from "./deps.ts";
import { PostBindingPageOptions } from "./types.ts";

const template = `<!DOCTYPE html>
<html>
<head>
  <title>SAML POST Binding</title>
</head>
<body>
  <form method="POST" action="{{{postUrl}}}" id="SAML{{messageType}}Form">
    <input type="hidden" name="SAML{{messageType}}" value="{{samlMessage}}" />
    <input type="hidden" name="RelayState" value="{{relayState}}" />
    <input id="SAMLSubmitButton" type="submit" value="Submit SAML {{messageType}}" />
  </form>
  {{#submitOnLoad}}
  <script>
    document.getElementById('SAMLSubmitButton').style.visibility = "hidden";
    document.getElementById('SAML{{messageType}}Form').submit();
  </script>
  {{/submitOnLoad}}
</body>
</html>`;

export default (options: PostBindingPageOptions): string => {
  if (!["Request", "Response"].includes(options.messageType)) {
    throw new Error("Invalid message type specified, must be one of: ['Request', 'Response']");
  }
  return mustache.render(template, options);
}