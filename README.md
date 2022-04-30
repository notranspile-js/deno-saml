SAML implementation for Deno
============================

[SAML 2.0](https://en.wikipedia.org/wiki/SAML_2.0) partial implementation that is tested to be
working correctly with [Azure](https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/add-application-portal-setup-sso) and [AWS](https://docs.aws.amazon.com/singlesignon/latest/userguide/samlapps.html) Identity Providers.

Can be used to impelement a [SAML Service Provider](https://en.wikipedia.org/wiki/Service_provider_(SAML)) or an [Identity Provider](https://en.wikipedia.org/wiki/Identity_provider_(SAML)) in a Deno application.

Limitations:

 - only [POST binding](https://en.wikipedia.org/wiki/SAML_2.0#HTTP_POST_Binding) is implemented
 - uses [xml2js](https://deno.land/x/xml2js) and [js2xml](https://deno.land/x/js2xml) libraries to work with SAML messages. These libraries don't preserve whitespaces between XML elements. It appeared that AWS uses whitespaces in the part of the SAML response that is signed (this is a likely cause of [problems to other SAML SP implementations too](https://stackoverflow.com/questions/71446457/aws-sso-signature-verification-problems)). Currently to verify AWS responses whitespaces are [restored manually](https://github.com/notranspile-js/deno-saml/blob/8a49d78835aa900daf498d58c39614be38e024f5/src/verifyResponse.ts#L88), this is a brittle approach and can be broken (response verification will fail with a false negative) if AWS will change whitespaces placing in future

Usage example
-------------

To run the example with Azure, run in `example` dir:

```
deno run -A serviceProvider.ts https://login.microsoftonline.com/[tenant UUID]/saml2 [client UUID]
```

With AWS run:

```
deno run -A serviceProvider.ts https://portal.sso.us-east-1.amazonaws.com/saml/assertion/[base64]
```

Open [http://localhost:8080/hello] in a browser, you will be redirected to Azure/AWS for auth and your username
will be displayed on a `hello` page after successfull authentication.


License information
-------------------

This project is released under the [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0).
