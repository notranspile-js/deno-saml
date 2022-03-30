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
      acsUrl: "http://127.0.0.1:8080/acs",
      destinationUrl: "http://127.0.0.1:8000/sso",
      issuerMetadataUrl: "http://127.0.0.1:8080/metadata",
    });
    const reqMsg = saml.toBase64Message(req);
    const html = saml.renderPostBindingPage({
      messageType: "Request",
      postUrl: "http://127.0.0.1:8000/sso",
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
    acsUrl: "http://127.0.0.1:8080/acs",
    metadataUrl: "http://127.0.0.1:8080/metadata",
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
  const valid = await saml.verifyResponse(resp);
  if (!valid) {
    throw new Error("Response verification failure");
  }
  const assertion = (resp["samlp:Response"] as saml.XmlObject)
    .Assertion as saml.XmlObject;
  const attr = (assertion.AttributeStatement as saml.XmlObject)
    .Attribute as saml.XmlObject;
  const user = (attr.AttributeValue as saml.XmlObject)
    ._text as string;
  const headers = new Headers();
  headers.set("Set-Cookie", `acs-user=${user}`);
  headers.set("Location", "http://127.0.0.1:8080/hello");
  return {
    status: 302,
    headers: headers,
  };
}

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
