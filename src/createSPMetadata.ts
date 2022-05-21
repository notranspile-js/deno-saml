import { dayjs } from "./deps.ts";
import { dateFormat } from "./common.ts";
import { SPMetadataOptions, XmlObject } from "./types.ts";

export default (options: SPMetadataOptions): XmlObject => {
  const validUntil = dayjs().utc().add(options.validMinutes, "minute");
  return {
    EntityDescriptor: {
      _attributes: {
        xmlns: "urn:oasis:names:tc:SAML:2.0:metadata",
        validUntil: validUntil.format(dateFormat),
        entityID: options.metadataUrl,
      },
      SPSSODescriptor: {
        _attributes: {
          xmlns: "urn:oasis:names:tc:SAML:2.0:metadata",
          validUntil: validUntil.format(dateFormat),
          protocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
          AuthnRequestsSigned: true,
          WantAssertionsSigned: true,
        },
        AssertionConsumerService: [
          {
            _attributes: {
              Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
              Location: options.acsUrl,
              index: 1,
            },
          },
        ],
      },
    },
  };
};
