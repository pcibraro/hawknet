using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace HawkNet
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
                ts = ConvertToUnixTimestamp(DateTime.UtcNow).ToString();

            var mac = CalculateMac(request, credential, ts, ext);

            var authParameter = string.Format("id=\"{0}\", ts=\"{1}\", mac=\"{2}\", ext=\"{3}\"",
                credential.Id, ts, mac, ext);

            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", authParameter);

            return base.SendAsync(request, cancellationToken);
        }

        public static double ConvertToUnixTimestamp(DateTime date)
        {
            var origin = new DateTime(1970, 1, 1, 0, 0, 0, 0);
            var diff = date.ToUniversalTime() - origin;
            return Math.Floor(diff.TotalSeconds);
        }

        public static string CalculateMac(HttpRequestMessage request, HawkCredential credential, string ts, string ext)
        {
            var host = (request.Headers.Host.IndexOf(':') > 0) ?
                request.Headers.Host.Substring(0, request.Headers.Host.IndexOf(':')) :
                request.Headers.Host;

            var normalized = ts + "\n" +
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

        public class HawkCredential
        {
            public string Id { get; set; }

            public string Key { get; set; }

            public string Algorithm { get; set; }

            public string User { get; set; }
        }

    }
}
