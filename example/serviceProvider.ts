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

import {
  io,
  saml,
  SimpleRequest,
  SimpleResponse,
  SimpleServer,
} from "./deps.ts";

let idpSsoUrl = "http://localhost:8000/sso";
let spAuthReqIssuer = `id-${crypto.randomUUID()}`;

function handleHello(req: SimpleRequest): SimpleResponse {
  let user = null;
  const cookie = req.headers.get("Cookie");
  if (cookie) {
    const parts = cookie.split("=");
    if ("acs-user" == parts[0]) {
      user = parts[1];
    }
  }
  if (null != user) {
    return {
      body: `Hello authenticated user, name: [${user}]`,
    };
  } else {
    const req = saml.createAuthnRequest({
      acsUrl: "http://localhost:8080/acs",
      destinationUrl: idpSsoUrl,
      issuer: spAuthReqIssuer,
    });
    const reqMsg = saml.toBase64Message(req);
    const html = saml.renderPostBindingPage({
      messageType: "Request",
      postUrl: idpSsoUrl,
      relayState: "foo",
      samlMessage: reqMsg,
      submitOnLoad: false,
    });
    const headers = new Headers();
    headers.set("content-type", "text/html");
    return {
      headers: headers,
      body: html,
    };
  }
}

function handleMetadata(_: SimpleRequest): SimpleResponse {
  const meta = saml.createSPMetadata({
    acsUrl: "http://localhost:8080/acs",
    metadataUrl: "http://localhost:8080/metadata",
    validMinutes: 42,
  });
  const xml = saml.toXml(meta);
  const headers = new Headers();
  headers.set("content-type", "application/xml");
  return {
    headers: headers,
    body: xml,
  };
}

async function handleACS(req: SimpleRequest): Promise<SimpleResponse> {
  const form = await req.formData();
  const respBase64 = form.get("SAMLResponse") as string;
  const resp = saml.parseBase64Message(respBase64);
  //console.log(JSON.stringify(resp, null, 4));
  const verified = await saml.verifyResponse(resp, {
    addSigInfoWhitespaces: idpSsoUrl.includes("amazonaws"),
  });
  if (!verified.success) {
    throw new Error("Response verification failure");
  }
  const user = verified.subjectNameId;
  const headers = new Headers();
  headers.set("Set-Cookie", `acs-user=${user}`);
  headers.set("Location", "http://localhost:8080/hello");
  return {
    status: 302,
    headers: headers,
  };
}

// main
// local: deno run -A serviceProvider.ts
// AWS: deno run -A serviceProvider.ts https://portal.sso.us-east-1.amazonaws.com/saml/assertion/[base64]
// Azure: deno run -A serviceProvider.ts https://login.microsoftonline.com/[tenant UUID]/saml2 [client UUID]

if (Deno.args.length > 0) {
  idpSsoUrl = Deno.args[0].trim();
  if (Deno.args.length > 1) {
    spAuthReqIssuer = Deno.args[1].trim();
  }
}
console.log(
  `Using IdP SSO URL: [${idpSsoUrl}], SP auth req issuer: [${spAuthReqIssuer}]`,
);

const server = new SimpleServer({
  listen: {
    port: 8080,
  },
  http: {
    path: "/",
    handler: async (req: SimpleRequest): Promise<SimpleResponse> => {
      if ("/metadata" == req.path) {
        return await handleMetadata(req);
      } else if ("/acs" == req.path) {
        return await handleACS(req);
      } else if ("/hello" == req.path) {
        return await handleHello(req);
      } else {
        return {
          status: 404,
          statusText: "404 Not Found",
          body:
            `404 Not Found, expected: [/metadata, /acs, /hello], actual: [${req.path}]`,
        };
      }
    },
  },
  logger: {
    info: (msg) => console.log(`server: ${msg}`),
    error: (msg) => console.log(`server: ${msg}`),
  },
});

console.log("SP server started on port: [8080], press Enter to stop");
for await (const _ of io.readLines(Deno.stdin)) {
  break;
}
console.log("Shutting down ...");
await server.close();
console.log("Shutdown complete");
