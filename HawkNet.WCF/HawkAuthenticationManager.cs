using System;
using System.Diagnostics;
using System.Collections.ObjectModel;
using System.Collections.Generic;
using System.ServiceModel.Channels;
using System.IdentityModel.Claims;
using System.IdentityModel.Policy;
using System.Security.Principal;
using System.ServiceModel;
using System.ServiceModel.Security;
using System.ServiceModel.Web;
using System.Security;
using System.Web;
using System.Linq;

namespace HawkNet.WCF
{
    class HawkAuthenticationManager : ServiceAuthenticationManager
    {
        const string HawkScheme = "Hawk";

        static TraceSource TraceSource = new TraceSource("HawkNet.WCF");

        Func<string, HawkCredential> credentials;
        int timeskewInSeconds;
        string schemeOverride;

        public HawkAuthenticationManager(Func<string, HawkCredential> credentials, int timeskewInSeconds, string schemeOverride)
            : base()
        {
            this.credentials = credentials;
            this.timeskewInSeconds = timeskewInSeconds;
            this.schemeOverride = schemeOverride;

            if (Trace.CorrelationManager.ActivityId == Guid.Empty)
                Trace.CorrelationManager.ActivityId = Guid.NewGuid();
        }

        public override ReadOnlyCollection<IAuthorizationPolicy> Authenticate(ReadOnlyCollection<IAuthorizationPolicy> authPolicy, Uri listenUri, ref Message requestMessage)
        {
            IPrincipal principal = ExtractCredentials(requestMessage);
            var policies = new List<IAuthorizationPolicy>();
            policies.Add(new HawkPrincipalAuthorizationPolicy());

            if (principal != null)
            {
                requestMessage.Properties["Principal"] = principal;
            }

            return policies.AsReadOnly();
        }

        private IPrincipal ExtractCredentials(Message requestMessage)
        {
            var request = (HttpRequestMessageProperty)requestMessage.Properties[HttpRequestMessageProperty.Name];

            var authHeader = request.Headers["Authorization"];
            if (authHeader != null && authHeader.StartsWith(HawkScheme, StringComparison.InvariantCultureIgnoreCase))
            {
                var hawk = authHeader.Substring(HawkScheme.Length).Trim();

                TraceSource.TraceInformation(string.Format("{0} - Received Auth header: {1}",
                    Trace.CorrelationManager.ActivityId, hawk));

                var uri = new Uri(HttpUtility.UrlDecode(requestMessage.Properties.Via.AbsoluteUri));

                var principal = Hawk.Authenticate(hawk,
                    request.Headers["host"],
                    request.Method,
                    new UriBuilder (uri) { Scheme = (!string.IsNullOrEmpty(schemeOverride)) ? schemeOverride : uri.Scheme }.Uri,
                    this.credentials,
                    this.timeskewInSeconds);

                return principal;
            }
            return null;
        }
    }
}
