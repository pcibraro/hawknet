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
            if (credential == null ||
                string.IsNullOrEmpty(credential.Id) ||
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

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, System.Threading.CancellationToken cancellationToken)
        {
            string payloadHash = null;

            if (this.includePayloadHash &&
                request.Method != HttpMethod.Get &&
                request.Content != null)
            {
                payloadHash = Hawk.CalculatePayloadHash(await request.Content.ReadAsStringAsync().ConfigureAwait(false),
                    request.Content.Headers.ContentType.MediaType,
                    credential);
            }

            request.SignRequest(credential,
                this.ext,
                this.ts,
                this.nonce,
                payloadHash);

            return await base.SendAsync(request, cancellationToken);
        }
    }
}
