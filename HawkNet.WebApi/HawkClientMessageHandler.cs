using System;
using System.Collections.Generic;
using System.Collections.Specialized;
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
        HawkCredential credential;
        string ext;
        string ts;
        string nonce;

        public HawkClientMessageHandler(HttpMessageHandler innerHandler, HawkCredential credential, string ext = "", string ts = null, string nonce = null)
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
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, System.Threading.CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(ts))
                ts = Hawk.ConvertToUnixTimestamp(DateTime.UtcNow).ToString();

            if(string.IsNullOrWhiteSpace(nonce))
                nonce = Hawk.GetRandomString(6);

            var mac = Hawk.CalculateMac(request.Headers.Host, 
                request.Method.ToString(), request.RequestUri, ext, ts, nonce, credential);

            var authParameter = string.Format("id=\"{0}\", ts=\"{1}\", nonce=\"{2}\", mac=\"{3}\", ext=\"{4}\"",
                credential.Id, ts, nonce, mac, ext);

            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", authParameter);

            return base.SendAsync(request, cancellationToken);
        }
    }
}
