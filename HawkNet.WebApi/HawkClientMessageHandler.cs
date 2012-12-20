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

        public HawkClientMessageHandler(HttpMessageHandler innerHandler, HawkCredential credential, string ext = "", string ts = null)
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
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, System.Threading.CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(ts))
                ts = Hawk.ConvertToUnixTimestamp(DateTime.UtcNow).ToString();

            var mac = Hawk.CalculateMac(request.Headers.Host, 
                request.Method.ToString(), request.RequestUri, ext, ts, credential);

            var authParameter = string.Format("id=\"{0}\", ts=\"{1}\", mac=\"{2}\", ext=\"{3}\"",
                credential.Id, ts, mac, ext);

            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", authParameter);

            return base.SendAsync(request, cancellationToken);
        }
    }
}
