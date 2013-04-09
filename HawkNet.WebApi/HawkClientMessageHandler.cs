using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace HawkNet.WebApi
{
    public class HawkClientMessageHandler : DelegatingHandler
    {
        static TraceSource TraceSource = new TraceSource("HawkNet");

        HawkCredential credential;
        string ext;
        DateTime? ts;
        string nonce;
        bool includePayloadHash;

        public HawkClientMessageHandler(HttpMessageHandler innerHandler, HawkCredential credential, string ext = "", DateTime? ts = null, string nonce = null, bool includePayloadHash = false)
            : base(innerHandler)
        {
            if (string.IsNullOrEmpty(credential.Id) ||
               string.IsNullOrEmpty(credential.Key) ||
               string.IsNullOrEmpty(credential.Algorithm))
            {
                throw new ArgumentException("Invalid Credential", "credential");
            }

            this.credential = credential;
            this.ext = ext;
            this.ts = ts;
            this.nonce = nonce;
            this.includePayloadHash = includePayloadHash;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, System.Threading.CancellationToken cancellationToken)
        {
            string payloadHash = null;

            if (this.includePayloadHash &&
                request.Method != HttpMethod.Get &&
                request.Content != null)
            {
                var hmac = System.Security.Cryptography.HMAC.Create(credential.Algorithm);
                hmac.Key = Encoding.ASCII.GetBytes(credential.Key);

                var task = request.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                var payload = task.GetAwaiter().GetResult();

                payloadHash = Convert.ToBase64String(hmac.ComputeHash(payload));
            }

            request.Headers.Host = request.RequestUri.Host;
            
            var auth = Hawk.GetAuthorizationHeader(request.Headers.Host,
                request.Method.ToString(),
                request.RequestUri,
                credential,
                this.ext,
                this.ts,
                this.nonce,
                payloadHash);

            TraceSource.TraceInformation(string.Format("Auth header {0}",
                auth));

            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", auth);

            return base.SendAsync(request, cancellationToken);
        }
    }
}
