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
            if (request.Headers.Authorization == null ||
                !string.Equals(request.Headers.Authorization.Scheme, Scheme))
            {
                return base.SendAsync(request, cancellationToken);
            }

            if (string.IsNullOrWhiteSpace(request.Headers.Authorization.Parameter))
            {
                return Unauthorized(request, "Invalid header format");
            }

            if (string.IsNullOrWhiteSpace(request.Headers.Host))
            {
                return Unauthorized(request, "Missing Host header");
            }
            
            IPrincipal principal = null;
            try
            {
                principal = Hawk.Authenticate(request.Headers.Authorization.Parameter, request.Headers.Host,
                        request.Method.ToString(), request.RequestUri, credentials);
            
            }
            catch(SecurityException ex)
            {
                return Unauthorized(request, ex.Message);
            }
            
            Thread.CurrentPrincipal = principal;
            if (HttpContext.Current != null)
            {
                HttpContext.Current.User = principal;
            }

            return base.SendAsync(request, cancellationToken);
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

        class NullTraceWriter : ITraceWriter
        {
            public void Trace(System.Net.Http.HttpRequestMessage request, string category, TraceLevel level, Action<TraceRecord> traceAction)
            {
            }
        }

        
    }
}
