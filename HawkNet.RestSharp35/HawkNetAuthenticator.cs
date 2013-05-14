using RestSharp;

namespace HawkNet.RestSharp35
{
    /// <summary>
    /// Class HawkNetAuthenticator implements a RestSharp IAuthenticator
    /// that works with the HawkNet authentication solution.
    /// </summary>
    public class HawkNetAuthenticator : IAuthenticator
    {
        #region fields

        private readonly HawkCredential _credential;

        #endregion

        #region constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="HawkNetAuthenticator"/> class.
        /// </summary>
        /// <param name="credential">The credential.</param>
        public HawkNetAuthenticator(HawkCredential credential)
        {
            _credential = credential;
        }

        #endregion

        #region IAuthenticator

        /// <summary>
        /// Authenticates the specified client and request using Hawk authentication.
        /// </summary>
        /// <param name="client">The RestSharp client instance use to submit the request.</param>
        /// <param name="request">The RestSharp request to execute.</param>
        public void Authenticate(IRestClient client, IRestRequest request)
        {
            var uri = client.BuildUri(request);
            var portSuffix = uri.Port != 80 ? ":" + uri.Port : "";
            var host = uri.Host + portSuffix;
            var method = request.Method.ToString();

            var header = Hawk.GetAuthorizationHeader(host, method, uri, _credential);

            request.AddHeader("Authorization", "Hawk " + header);
        }

        #endregion
    }
}