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

export type XmlNode =
  | string
  | boolean
  | number
  | XmlNode[]
  | { [property: string]: XmlNode };
export type XmlObject = Record<string, XmlNode>;

export type AuthnRequestOptions = {
  acsUrl: string;
  destinationUrl: string;
  issuer: string;
};

export type ResponseOptions = {
  requestId: string;
  destinationUrl: string;
  issuerUrl: string;
  nameId: string;
  notAfterMinutes: number;
  audience: string;
  sessionId: string;
  assertionAttributes: Record<string, string>;
};

export type SignOptions = {
  response: XmlObject;
  privateKeyPkcs8Pem: string;
  privateKeyAlgoritmName?: string;
  privateKeyHash?: string;
  certificateX509Pem: string;
};

export type VerifyOptions = {
  addSigInfoWhitespaces?: boolean;
  stripAttributesNamespaceXs?: boolean;
  keyInfoNamespace?: string;
};

export type VerifyPeriod = {
  from: string;
  to: string;
};

export type VerifyResult = {
  success: boolean;
  subjectNameId: string;
  certificateX509Pem: string;
  period: VerifyPeriod;
  attributes: Record<string, string>;
};

export type SPMetadataOptions = {
  validMinutes: number;
  acsUrl: string;
  metadataUrl: string;
};

export type IdPMetadataOptions = {
  id: string;
  validMinutes: number;
  entityId: string;
  certificateX509Pem: string;
  httpPostBindingUrl: string;
};

export type PostBindingPageOptions = {
  postUrl: string;
  messageType: string;
  samlMessage: string;
  relayState: string;
  submitOnLoad: boolean;
};
