using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace HawkNet
{
    public static class HttpRequestMessageExtensions
    {
        /// <summary>
        /// Adds the Hawk authorization header to request message
        /// </summary>
        /// <param name="request">Request instance</param>
        /// <param name="credential">Hawk credentials</param>
        /// <param name="ext">Optional extension</param>
        /// <param name="ts">Timestamp</param>
        /// <param name="nonce">Random nonce</param>
        /// <param name="payloadHash">Request payload hash</param>
        public static void SignRequest(this HttpRequestMessage request,
            HawkCredential credential,
            string ext = null,
            DateTime? ts = null,
            string nonce = null,
            string payloadHash = null)
        {
            var host = (request.Headers.Host != null) ? request.Headers.Host :
                request.RequestUri.Host +
                    ((request.RequestUri.Port != 80) ? ":" + request.RequestUri.Port : "");

            var hawk = Hawk.GetAuthorizationHeader(host,
                request.Method.ToString(),
                request.RequestUri,
                credential,
                ext,
                ts,
                nonce,
                payloadHash);

            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", hawk);
        }

        /// <summary>
        /// Authenticates an upcoming request message
        /// </summary>
        /// <param name="request">Http request instance</param>
        /// <param name="credentials">A method for searching across the available credentials</param>
        /// <param name="timestampSkewSec">Time skew in seconds for timestamp verification</param>
        /// <returns>A new ClaimsPrincipal instance representing the authenticated user</returns>
        public static async Task<IPrincipal> AuthenticateAsync(this HttpRequestMessage request, Func<string, Task<HawkCredential>> credentials, int timestampSkewSec = 60)
        {
            if (request.Method == HttpMethod.Get &&
                !string.IsNullOrEmpty(request.RequestUri.Query))
            {
                var query = HttpUtility.ParseQueryString(request.RequestUri.Query);
                if (query["bewit"] != null)
                {
                    return await Hawk.AuthenticateBewitAsync(query["bewit"],
                        request.Headers.Host,
                        request.RequestUri,
                        credentials);
                }
            }

            Func<Task<string>> requestPayload = (async () =>
            {
                var payload = await request.Content
                    .ReadAsStringAsync()
                    .ConfigureAwait(false);

                return payload;
            });

           return await Hawk.AuthenticateAsync(request.Headers.Authorization.Parameter,
                request.Headers.Host,
                request.Method.ToString(),
                request.RequestUri,
                credentials,
                timestampSkewSec,
                requestPayload,
                (request.Content != null && 
                request.Content.Headers.ContentType != null) 
                    ? request.Content.Headers.ContentType.MediaType : null);
        }
    }
}
