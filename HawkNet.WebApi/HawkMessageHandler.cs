using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http.Tracing;

namespace HawkNet.WebApi
{
    /// <summary>
    /// A HttpMessageHandler implementation for being used in the ASP.NET Web API 
    /// runtime pipeline.
    /// </summary>
    public class HawkMessageHandler : DelegatingHandler
    {
        static TraceSource TraceSource = new TraceSource("HawkNet");

        const string Scheme = "Hawk";
        
        Func<string, Task<HawkCredential>> credentials;
        int timeskewInSeconds = 60;
        bool includeServerAuthorization;

        public HawkMessageHandler(Func<string, Task<HawkCredential>> credentials, 
            int timeskewInSeconds = 60, 
            bool includeServerAuthorization = false)
            : base()
        {
            if (credentials == null)
                throw new ArgumentNullException("credentials");

            this.credentials = credentials;
            this.timeskewInSeconds = timeskewInSeconds;
            this.includeServerAuthorization = includeServerAuthorization;
        }

        public HawkMessageHandler(HttpMessageHandler innerHandler, 
            Func<string, Task<HawkCredential>> credentials, 
            int timeskewInSeconds = 60,
            bool includeServerAuthorization = false)
            : base(innerHandler)
        {
            if (credentials == null)
                throw new ArgumentNullException("credentials");

            this.credentials = credentials;
            this.timeskewInSeconds = timeskewInSeconds;
            this.includeServerAuthorization = includeServerAuthorization;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, System.Threading.CancellationToken cancellationToken)
        {
            IPrincipal principal = null;

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
                            .AuthenticateAsync(credentials, this.timeskewInSeconds);
                    }
                    catch (SecurityException ex)
                    {
                        return ToResponse(request, HttpStatusCode.Unauthorized, ex.Message);
                    }

                    Thread.CurrentPrincipal = principal;
                    if (HttpContext.Current != null)
                    {
                        HttpContext.Current.User = principal;
                    }

                    var response = await base.SendAsync(request, cancellationToken);

                    if (!this.includeServerAuthorization)
                        return response;

                    return await AuthenticateResponse(request.Headers.Authorization.Parameter,
                                request.Headers.Host,
                                request.Method.ToString(),
                                request.RequestUri,
                                credentials,
                                response);
                }
            }
            
            if (request.Headers.Authorization != null &&
                !string.Equals(request.Headers.Authorization.Scheme, Scheme))
            {
                TraceSource.TraceInformation(string.Format("Authorization skipped. Schema found {0}",
                        request.Headers.Authorization.Scheme));

                return await base.SendAsync(request, cancellationToken);
            }

            if (request.Headers.Authorization == null ||
                string.IsNullOrWhiteSpace(request.Headers.Authorization.Scheme))
            {
                TraceSource.TraceInformation("Authorization header not found");

                var response = await base.SendAsync(request, cancellationToken);

                if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    return ChallengeResponse(request);
                }
                else
                {
                    return response;
                }
            }
            else
            {
                if (string.IsNullOrWhiteSpace(request.Headers.Authorization.Parameter))
                {
                    return ToResponse(request, HttpStatusCode.BadRequest, "Invalid header format");
                }

                if (string.IsNullOrWhiteSpace(request.Headers.Host))
                {
                    return ToResponse(request, HttpStatusCode.BadRequest, "Missing Host header");
                }

                try
                {
                    principal = await request.AuthenticateAsync(credentials, this.timeskewInSeconds);

                }
                catch (SecurityException ex)
                {
                    TraceSource.TraceData(TraceEventType.Error, 0, ex.ToString());

                    return ToResponse(request, HttpStatusCode.Unauthorized, ex.Message);
                }

                Thread.CurrentPrincipal = principal;
                if (HttpContext.Current != null)
                {
                    HttpContext.Current.User = principal;
                }

                var response = await base.SendAsync(request, cancellationToken);

                if (!this.includeServerAuthorization)
                    return response;
                
                return await AuthenticateResponse(request.Headers.Authorization.Parameter,
                            request.Headers.Host,
                            request.Method.ToString(),
                            request.RequestUri,
                            credentials,
                            response);
            }
        }

        private static HttpResponseMessage ChallengeResponse(HttpRequestMessage request)
        {
            var ts = Hawk.ConvertToUnixTimestamp(DateTime.Now).ToString();
            var challenge = string.Format("ts=\"{0}\" ntp=\"{1}\"",
                ts, "pool.ntp.org");

            var response = request.CreateResponse(HttpStatusCode.Unauthorized);
            response.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue(Scheme, challenge));

            return response;
        }

        private static HttpResponseMessage ToResponse(HttpRequestMessage request, HttpStatusCode code, string message)
        {
            var response = request.CreateResponse(code);
            response.ReasonPhrase = message;
            response.Content = new StringContent(message);

            return response;
        }

        private static async Task<HttpResponseMessage> AuthenticateResponse(string authorization,
            string host, 
            string method,
            Uri uri,
            Func<string, Task<HawkCredential>> credentials,
            HttpResponseMessage response)
        {
            var attributes = Hawk.ParseAttributes(authorization);

            var credential = await credentials(attributes["id"]);

            var payload = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);

            var hmac = System.Security.Cryptography.HMAC.Create(credential.Algorithm);
            hmac.Key = Encoding.UTF8.GetBytes(credential.Key);
            var hash = Convert.ToBase64String(hmac.ComputeHash(payload));

            var serverAuthorization = Hawk.GetAuthorizationHeader(host,
                method,
                uri,
                credential,
                null,
                null,
                attributes["nonce"],
                hash);

            response.Headers.Add("Server-Authorization", "Hawk " + serverAuthorization);

            return response;
            
        }

    }
}
