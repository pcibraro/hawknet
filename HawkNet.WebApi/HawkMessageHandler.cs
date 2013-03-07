using System;
using System.Collections.Generic;
using System.Collections.Specialized;
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
    public class HawkMessageHandler : DelegatingHandler
    {
        const string Scheme = "Hawk";
        
        Func<string, HawkCredential> credentials;
        ITraceWriter traceWriter;

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
            IPrincipal principal = null;

            if (request.Method == HttpMethod.Get &&
                request.RequestUri != null &&
                !string.IsNullOrEmpty(request.RequestUri.Query))
            {
                var query = HttpUtility.ParseQueryString(request.RequestUri.Query);
                if (query["bewit"] != null)
                {
                    try
                    {
                        principal = Hawk.Authenticate(request, credentials);

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
                return base.SendAsync(request, cancellationToken);
            }

            if (request.Headers.Authorization == null ||
                string.IsNullOrWhiteSpace(request.Headers.Authorization.Scheme))
            {
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
                    principal = Hawk.Authenticate(request, credentials);

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

        private static HttpResponseMessage ChallengeResponse(HttpRequestMessage request)
        {
            //var tsc = new TaskCompletionSource<HttpResponseMessage>();

            var ts = Hawk.ConvertToUnixTimestamp(DateTime.Now).ToString();
            var challenge = string.Format("ts=\"{0}\" ntp=\"{1}\"",
                ts, "pool.ntp.org");

            var response = request.CreateResponse(HttpStatusCode.Unauthorized);
            response.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue(Scheme, challenge));

            return response;

            //tsc.SetResult(response);

            //return tsc.Task;
        }

        private static Task<HttpResponseMessage> ToResponse(HttpRequestMessage request, HttpStatusCode code, string message)
        {
            var tsc = new TaskCompletionSource<HttpResponseMessage>();

            var response = request.CreateResponse(code);
            response.ReasonPhrase = message;
            
            tsc.SetResult(response);

            return tsc.Task;
        }

        class NullTraceWriter : ITraceWriter
        {
            public void Trace(System.Net.Http.HttpRequestMessage request, string category, TraceLevel level, Action<TraceRecord> traceAction)
            {
            }
        }

        
    }
}
