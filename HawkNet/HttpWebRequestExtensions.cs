using HawkNet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;

namespace HawkNet
{
    public static class HttpWebRequestExtensions
    {
        /// <summary>
        /// Adds the Hawk authorization header to a request message
        /// </summary>
        /// <param name="request">Request instance</param>
        /// <param name="credential">Hawk credentials</param>
        public static void SignRequest(this HttpWebRequest request, HawkCredential credential)
        {
            SignRequest(request, credential, null, null, null, null);
        }

        /// <summary>
        /// Adds the Hawk Authorization header to a HttpWebRequest instance
        /// </summary>
        /// <param name="request">Request instance</param>
        /// <param name="credential">Hawk credentials</param>
        /// <param name="ext">Optional extension</param>
        /// <param name="ts">Timestamp</param>
        /// <param name="nonce">Random nonce</param>
        /// <param name="payloadHash">Request payload hash</param>
        public static void SignRequest(this HttpWebRequest request, 
            HawkCredential credential, 
            string ext, 
            DateTime? ts, 
            string nonce,
            string payloadHash)
        {
#if NET45
            var host = (request.Host != null) ? request.Host :
                request.RequestUri.Host +
                    ((request.RequestUri.Port != 80) ? ":" + request.RequestUri.Port : "");
#else
            var host = request.RequestUri.Host +
                    ((request.RequestUri.Port != 80) ? ":" + request.RequestUri.Port : "");
#endif
            var hawk = Hawk.GetAuthorizationHeader(host,
                request.Method,
                request.RequestUri,
                credential,
                ext,
                ts,
                nonce,
                payloadHash);

            request.Headers.Add("Authorization", "Hawk " + hawk);
        }
    }
}
