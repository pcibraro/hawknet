using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Http.Filters;

namespace HawkNet.WebApi
{
    public class HawkAuthentication : Attribute, IAuthenticationFilter
    {
        static TraceSource TraceSource = new TraceSource("HawkNet");

        const string Scheme = "Hawk";

        IHawkCredentialRepository repository;
        int timeskewInSeconds;
        bool includeServerAuthorization = false;

        /// <summary>
        /// Creates a new instance of HawkActionFilter using a type for
        /// instanciating a IHawkCredentialRepository
        /// </summary>
        /// <param name="hawkCredentialRepositoryType">IHawkCredentialRepository type</param>
        public HawkAuthentication(Type hawkCredentialRepositoryType,
            int timeskewInSeconds = 60,
            bool includeServerAuthorization = false)
            : base()
        {
            if (hawkCredentialRepositoryType == null)
                throw new ArgumentNullException("hawkCredentialRepositoryType");

            if (!hawkCredentialRepositoryType.GetInterfaces()
                .Contains(typeof(IHawkCredentialRepository)))
            {
                throw new ArgumentException(
                    "Must derive from IHawkCredentialRepository",
                    "hawkCredentialRepositoryType");
            }

            var instance = (IHawkCredentialRepository)Activator
                .CreateInstance(hawkCredentialRepositoryType);

            this.repository = instance;
            this.timeskewInSeconds = timeskewInSeconds;
            this.includeServerAuthorization = includeServerAuthorization;
        }

        public bool AllowMultiple
        {
            get
            {
                return false;
            }
        }

        public async Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {
            IPrincipal principal = null;

            var request = context.Request;

            if (request.Method == HttpMethod.Get &&
                request.RequestUri != null &&
                !string.IsNullOrEmpty(request.RequestUri.Query))
            {
                var query = HttpUtility.ParseQueryString(request.RequestUri.Query);
                if (query["bewit"] != null)
                {
                    TraceSource.TraceInformation(string.Format("Bewit found {0}",
                        query["bewit"]));
                    try
                    {
                        principal = await request
                            .AuthenticateAsync(
                            this.repository.GetCredentialsAsync, 
                            this.timeskewInSeconds);
                    }
                    catch (SecurityException ex)
                    {
                        TraceSource.TraceEvent(TraceEventType.Error, 
                            0, 
                            "The request could not be authenticated. " + ex.ToString());
                        return;
                    }

                    Thread.CurrentPrincipal = principal;
                    context.Principal = principal;
                }
            }

            if (request.Headers.Authorization != null &&
                !string.Equals(request.Headers.Authorization.Scheme, Scheme))
            {
                TraceSource.TraceInformation(string.Format("Authorization skipped. Schema found {0}",
                        request.Headers.Authorization.Scheme));

                return;
            }

            if (request.Headers.Authorization == null ||
                string.IsNullOrWhiteSpace(request.Headers.Authorization.Scheme))
            {
                TraceSource.TraceInformation("Authorization header not found");

                return;
            }
            else
            {
                if (string.IsNullOrWhiteSpace(request.Headers.Authorization.Parameter))
                {
                    TraceSource.TraceInformation("Invalid header format");
                    return;
                }

                if (string.IsNullOrWhiteSpace(request.Headers.Host))
                {
                    TraceSource.TraceInformation("Missing Host header");
                    return;
                }

                try
                {
                    principal = await request.AuthenticateAsync(this.repository.GetCredentialsAsync, 
                    this.timeskewInSeconds);
                }
                catch (SecurityException ex)
                {
                    TraceSource.TraceData(TraceEventType.Error, 0, ex.ToString());

                    return;
                }

                Thread.CurrentPrincipal = principal;
                context.Principal = principal;
            }
        }

        public Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken)
        {
            context.Result = new ResultWithChallenge(context.Result,
                context.Request,
                this.includeServerAuthorization,
                this.repository.GetCredentialsAsync);
           
            return Task.FromResult<object>(null);
        }

        public class ResultWithChallenge : IHttpActionResult
        {
            IHttpActionResult next;
            HttpRequestMessage request;
            bool includeServerAuthorization;
            Func<string, Task<HawkCredential>> credentials;

            public ResultWithChallenge(IHttpActionResult next, 
                HttpRequestMessage request,
                bool includeServerAuthorization,
                Func<string, Task<HawkCredential>> credentials)
            {
                this.next = next;
                this.includeServerAuthorization = includeServerAuthorization;
                this.credentials = credentials;
                this.request = request;
            }

            public async Task<HttpResponseMessage> ExecuteAsync(
                                        CancellationToken cancellationToken)
            {
                var response = await next.ExecuteAsync(cancellationToken);
                if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    var ts = Hawk.ConvertToUnixTimestamp(DateTime.Now).ToString();
                    var challenge = string.Format("ts=\"{0}\" ntp=\"{1}\"",
                        ts, "pool.ntp.org");

                    response.Headers.WwwAuthenticate.Add(
                           new AuthenticationHeaderValue(Scheme, challenge));
                }
                else if(this.includeServerAuthorization)
                {
                    
                    if (request.Method == HttpMethod.Get &&
                        request.RequestUri != null &&
                        !string.IsNullOrEmpty(request.RequestUri.Query))
                    {
                        var query = HttpUtility.ParseQueryString(request.RequestUri.Query);
                        if (query["bewit"] != null)
                        {
                            var decodedBewit = Encoding.UTF8.GetString(
                                Convert.FromBase64String(query["bewit"]));

                            var bewitParts = decodedBewit.Split('\\');

                            return await AuthenticateResponse(
                                        bewitParts[0],
                                        bewitParts[1],
                                        null,
                                        request.Headers.Host,
                                        request.Method.ToString(),
                                        request.RequestUri,
                                        response.Content.Headers.ContentType.MediaType,
                                        credentials,
                                        response);
                        }
                    }

                    if (request.Headers.Authorization != null &&
                        !string.IsNullOrWhiteSpace(request.Headers.Authorization.Scheme) &&
                        request.Headers.Authorization.Scheme.Equals(Scheme, StringComparison.InvariantCultureIgnoreCase))

                    {
                        var attributes = Hawk.ParseAttributes(request.Headers.Authorization.Parameter);

                        return await AuthenticateResponse(
                                    attributes["id"],
                                    attributes["ts"],
                                    attributes["nonce"],
                                    request.Headers.Host,
                                    request.Method.ToString(),
                                    request.RequestUri,
                                    response.Content.Headers.ContentType.MediaType,
                                    credentials,
                                    response);
                    }
                }

                return response;
            }

            private static async Task<HttpResponseMessage> AuthenticateResponse(string id,
                string ts,
                string nonce,
                string host,
                string method,
                Uri uri,
                string mediaType,
                Func<string, Task<HawkCredential>> credentials,
                HttpResponseMessage response)
            {

                var credential = await credentials(id);

                var payload = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                var hash = Hawk.CalculatePayloadHash(payload, mediaType, credential);

                var mac = Hawk.CalculateMac(host,
                    method,
                    uri,
                    null,
                    ts,
                    nonce,
                    credential,
                    "response",
                    hash);

                var serverAuthorization = string.Format("mac=\"{0}\", hash=\"{1}\"",
                        mac, hash);

                response.Headers.Add("Server-Authorization", "Hawk " + serverAuthorization);

                return response;

            }
        }
    }


}
