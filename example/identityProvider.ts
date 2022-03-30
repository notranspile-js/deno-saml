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
  path,
  saml,
  SimpleRequest,
  SimpleResponse,
  SimpleServer,
} from "./deps.ts";

async function handleMetadata(_: SimpleRequest): Promise<SimpleResponse> {
  const scriptPath = path.fromFileUrl(import.meta.url);
  const dir = path.dirname(scriptPath);
  const certPath = path.join(dir, "saml_test_cert_x509.pem");
  const cert = await Deno.readTextFile(certPath);

  const meta = saml.createIdPMetadata({
    certificateX509Pem: cert,
    entityId: "http://127.0.0.1:8000/metadata",
    httpPostBindingUrl: "http://127.0.0.1:8000/sso",
    id: "id-foo",
    validMinutes: 42,
  });
  const headers = new Headers();
  headers.set("content-type", "application/xml");
  return {
    headers: headers,
    body: saml.toXml(meta),
  };
}

async function handleSSO(req: SimpleRequest): Promise<SimpleResponse> {
  if ("POST" != req.method) {
    return {
      status: 405,
      statusText: "405 Method Not Allowed",
      body: `405 Method Not Allowed, expected: [POST], actual: [${req.method}]`,
    };
  }
  const scriptPath = path.fromFileUrl(import.meta.url);
  const dir = path.dirname(scriptPath);
  const certPath = path.join(dir, "saml_test_cert_x509.pem");
  const cert = await Deno.readTextFile(certPath);
  const keyPath = path.join(dir, "saml_test_private_key_pkcs8.pem");
  const key = await Deno.readTextFile(keyPath);
  
  const form = await req.formData();
  const relayState = form.get("RelayState") as string ?? "";
  const authnReqMessage = form.get("SAMLRequest") as string;
  const authnReq = saml.parseBase64Message(authnReqMessage);
  const reqAttrs = (authnReq["samlp:AuthnRequest"] as saml.XmlObject)
    ._attributes as saml.XmlObject;
  const resp = saml.createResponse({
    assertionAttributes: {
      user: "Foo Bar",
    },
    audience: "foo",
    destinationUrl: reqAttrs.AssertionConsumerServiceURL as string,
    issuerUrl: "http://127.0.0.1:8000/sso",
    nameId: "bar",
    notAfterMinutes: 42,
    requestId: reqAttrs.ID as string,
    sessionId: `id-${crypto.randomUUID()}`,
  });
  const respSigned = await saml.signResponse({
    certificateX509Pem: cert,
    privateKeyPkcs8Pem: key,
    response: resp
  });
  const respMessage = saml.toBase64Message(respSigned);
  const html = saml.renderPostBindingPage({
    messageType: "Response",
    postUrl: reqAttrs.AssertionConsumerServiceURL as string,
    relayState: relayState,
    samlMessage: respMessage,
    submitOnLoad: false,
  });
  const headers = new Headers();
  headers.set("content-type", "text/html");
  return {
    headers: headers,
    body: html,
  };
}


// main

const server = new SimpleServer({
  listen: {
    port: 8000,
  },
  http: {
    path: "/",
    handler: async (req: SimpleRequest): Promise<SimpleResponse> => {
      if ("/metadata" == req.path) {
        return await handleMetadata(req);
      } else if ("/sso" == req.path) {
        return await handleSSO(req);
      } else {
        return {
          status: 404,
          statusText: "404 Not Found",
          body:
            `404 Not Found, expected: [/metadata, /sso], actual: [${req.path}]`,
        };
      }
    },
  },
  logger: {
    info: (msg) => console.log(`server: ${msg}`),
    error: (msg) => console.log(`server: ${msg}`),
  },
});

console.log("IdP server started on port: [8000], press Enter to stop");
for await (const _ of io.readLines(Deno.stdin)) {
  break;
}
console.log("Shutting down ...");
await server.close();
console.log("Shutdown complete");
