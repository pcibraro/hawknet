hawknet
=======

Hawk protocol implementation for .NET. Hawk is an HTTP authentication scheme using a message authentication code (MAC) algorithm to provide partial HTTP request cryptographic verification.

The project includes a basic library for generating/verifying a Hawk authorization header, and set of integration projects for existing web frameworks such as ASP.NET Web API or ServiceStack. An OWIN handler is also included, which can used for any OWIN compatible implementation.

For use in WCF you'd include something like this:

```xml
<serviceBehaviors>
<behavior name="HawkAuthenticatedService">
  <hawk sendChallenge="false" schemeOverride="https">
    <credentials>
      <credential user="yourusername" id="yourid" key="your key should be long and random and NOT THIS" algorithm="sha256"/>
    </credentials>
  </hawk>
</behavior>
</serviceBehavior>
```

And apply it on your service like this:
```xml
<service name="Assembly.HawkAuthenticatedService" behaviorConfiguration="HawkAuthenticatedService">
```
