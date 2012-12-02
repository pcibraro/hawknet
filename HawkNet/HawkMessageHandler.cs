using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http.Tracing;

namespace HawkNet
{
    public class HawkMessageHandler : DelegatingHandler
    {
        const string Scheme = "Hawk";
        readonly static string[] RequiredAttributes = { "id", "ts", "mac" };
        readonly static string[] OptionalAttributes = { "ext" };
        readonly static string[] SupportedAttributes;
        readonly static string[] SupportedAlgorithms = { "HMACSHA1", "HMACSHA256" };
        
        Func<string, HawkCredential> credentials;
        ITraceWriter traceWriter;

        static HawkMessageHandler()
        {
            SupportedAttributes = RequiredAttributes.Concat(OptionalAttributes).ToArray();
        }


        public HawkMessageHandler(Func<string, HawkCredential> credentials, ITraceWriter traceWriter)
            : base()
        {
            this.credentials = credentials;
            this.traceWriter = traceWriter;
        }

        public HawkMessageHandler(Func<string, HawkCredential> credentials)
            : this(credentials, new NullTraceWriter())
        {
        }

        public HawkMessageHandler(HttpMessageHandler innerHandler, Func<string, HawkCredential> credentials)
            : this(innerHandler, credentials, new NullTraceWriter())
        {
        }

        public HawkMessageHandler(HttpMessageHandler innerHandler, Func<string, HawkCredential> credentials, ITraceWriter traceWriter)
            : base(innerHandler)
        {
            this.credentials = credentials;
            this.traceWriter = traceWriter;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, System.Threading.CancellationToken cancellationToken)
        {
            if (request.Headers.Authorization == null)
            {
                return Unauthorized(request, "Missing Authorization header");  
            }

            if (!string.Equals(request.Headers.Authorization.Scheme, Scheme))
            {
                return Unauthorized(request, "Incorrect scheme");
            }

            if (string.IsNullOrWhiteSpace(request.Headers.Authorization.Parameter))
            {
                return Unauthorized(request, "Invalid header format");
            }

            if (string.IsNullOrWhiteSpace(request.Headers.Host))
            {
                return Unauthorized(request, "Missing Host header");
            }

            var attributes = ParseAttributes(request.Headers.Authorization.Parameter);
            
            if(!RequiredAttributes.All(a => attributes.AllKeys.Any(k => k == a)))
            {
                return Unauthorized(request, "Missing attributes");
            }

            if (!attributes.AllKeys.All(a => SupportedAttributes.Any(k => k == a)))
            {
                return Unauthorized(request, "Unknown attributes");
            }

            HawkCredential userCredentials = null;
            try
            {
                userCredentials = credentials(attributes["id"]);
            }
            catch (Exception ex)
            {
                traceWriter.Error(request, "hawk", ex);

                return Unauthorized(request, "Unknown user");
            }

            if (userCredentials == null)
            {
                traceWriter.Warn(request, "hawk", "Missing credentials for id = {0}", attributes["id"]);

                return Unauthorized(request, "Missing credentials");
            }

            if (string.IsNullOrWhiteSpace(userCredentials.Algorithm) ||
                string.IsNullOrWhiteSpace(userCredentials.Key))
            {
                traceWriter.Warn(request, "hawk", "Invalid credentials for id = {0}", attributes["id"]);

                return Unauthorized(request, "Invalid credentials");
            }

            if (!SupportedAlgorithms.Any(a => string.Equals(a, userCredentials.Algorithm, StringComparison.InvariantCultureIgnoreCase)))
            {
                traceWriter.Warn(request, "hawk", "Unsuported algorithm for id = {0}", attributes["id"]);

                return Unauthorized(request, "Unknown algorithm");
            }

            var mac = CalculateMac(request, attributes, userCredentials);
            if (!mac.Equals(attributes["mac"]))
            {
                return Unauthorized(request, "Bad mac");
            }

            var identity = new HawkIdentity((userCredentials.User != null) ? userCredentials.User : "", userCredentials);
            var principal = new HawkPrincipal(identity, new string[] { });

            Thread.CurrentPrincipal = principal;
            if (HttpContext.Current != null)
            {
                HttpContext.Current.User = principal;
            }

            return base.SendAsync(request, cancellationToken);
        }

        public static string CalculateMac(HttpRequestMessage request, NameValueCollection attributes, HawkCredential credential)
        {
            var ext = attributes["ext"];

            var host = (request.Headers.Host.IndexOf(':') > 0) ?
                request.Headers.Host.Substring(0, request.Headers.Host.IndexOf(':')) : 
                request.Headers.Host;

            var normalized = attributes["ts"] + "\n" +
                     request.Method.Method.ToUpper() + "\n" +
                     request.RequestUri.PathAndQuery + "\n" +
                     host.ToLower() + "\n" +
                     request.RequestUri.Port.ToString() + "\n" +
                     ((ext != null) ? ext : "") + "\n";

            var keyBytes = Encoding.ASCII.GetBytes(credential.Key);
            var messageBytes = Encoding.ASCII.GetBytes(normalized);

            var hmac = HMAC.Create(credential.Algorithm);
            hmac.Key = keyBytes;

            var mac = hmac.ComputeHash(messageBytes);

            return Convert.ToBase64String(mac);
        }

        private static Task<HttpResponseMessage> Unauthorized(HttpRequestMessage request, string message)
        {
            var tsc = new TaskCompletionSource<HttpResponseMessage>();
            
            var response = request.CreateResponse(HttpStatusCode.Unauthorized);
            response.ReasonPhrase = message;
            response.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue(Scheme, "error='" + message + "'"));

            tsc.SetResult(response);

            return tsc.Task;
        }

        private NameValueCollection ParseAttributes(string auth)
        {
            var allAttributes = new NameValueCollection();

            foreach (var attribute in auth.Split(','))
            {
                var index = attribute.IndexOf('=');
                if (index > 0)
                {
                    var key = attribute.Substring(0, index).Trim();
                    var value = attribute.Substring(index + 1).Trim();

                    if (value.StartsWith("\""))
                        value = value.Substring(1, value.Length -2);

                    allAttributes.Add(key, value);
                }
            }

            return allAttributes;
        }

        class NullTraceWriter : ITraceWriter
        {
            public void Trace(System.Net.Http.HttpRequestMessage request, string category, TraceLevel level, Action<TraceRecord> traceAction)
            {
            }
        }

        public class HawkCredential
        {
            public string Id { get; set; }

            public string Key { get; set; }

            public string Algorithm { get; set; }

            public string User { get; set; }
        }

        public class HawkPrincipal : GenericPrincipal
        {
            public HawkPrincipal(IIdentity identity, string[] roles)
                : base(identity, roles)
            {
            }
        }

        public class HawkIdentity : GenericIdentity
        {
            public HawkIdentity(string name, HawkCredential credentials)
                : base(name, "hawk")
            {
                this.Credentials = credentials;
            }

            public HawkCredential Credentials { get; private set; }
        }
    }
}
