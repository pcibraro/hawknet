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
        
        Func<string, HawkCredential> credentials;

        public HawkMessageHandler(Func<string, HawkCredential> credentials)
            : base()
        {
            if (credentials == null)
                throw new ArgumentNullException("credentials");

            this.credentials = credentials;
        }

        public HawkMessageHandler(HttpMessageHandler innerHandler, Func<string, HawkCredential> credentials)
            : base(innerHandler)
        {
            if (credentials == null)
                throw new ArgumentNullException("credentials");

            this.credentials = credentials;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, System.Threading.CancellationToken cancellationToken)
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
                        principal = request.Authenticate(credentials);

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

                    return base.SendAsync(request, cancellationToken);
                }
            }
            
            if (request.Headers.Authorization != null &&
                !string.Equals(request.Headers.Authorization.Scheme, Scheme))
            {
                TraceSource.TraceInformation(string.Format("Authorization skipped. Schema found {0}",
                        request.Headers.Authorization.Scheme));

                return base.SendAsync(request, cancellationToken);
            }

            if (request.Headers.Authorization == null ||
                string.IsNullOrWhiteSpace(request.Headers.Authorization.Scheme))
            {
                TraceSource.TraceInformation("Authorization header not found");

                return base.SendAsync(request, cancellationToken).ContinueWith<HttpResponseMessage>(r =>
                    {
                        if (r.Result.StatusCode == HttpStatusCode.Unauthorized)
                        {
                            return ChallengeResponse(request);
                        }

                        return r.Result;
                    });
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
                    principal = request.Authenticate(credentials);

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

                return base.SendAsync(request, cancellationToken);
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

        private static Task<HttpResponseMessage> ToResponse(HttpRequestMessage request, HttpStatusCode code, string message)
        {
            var tsc = new TaskCompletionSource<HttpResponseMessage>();

            var response = request.CreateResponse(code);
            response.ReasonPhrase = message;
            response.Content = new StringContent(message);
            
            tsc.SetResult(response);

            return tsc.Task;
        }
    }
}
