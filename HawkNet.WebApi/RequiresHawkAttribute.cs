using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http.Filters;

namespace HawkNet.WebApi
{
    /// <summary>
    /// An simple alternative for the HawkMessageHandler in case a message handler can not be 
    /// used. This implementation does not return a challenge in case an authorization header
    /// is not provided.
    /// </summary>
    [AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, Inherited = true)]
    public class RequiresHawkAttribute : AuthorizationFilterAttribute
    {
        static TraceSource TraceSource = new TraceSource("HawkNet");

        const string Scheme = "Hawk";
        
        Func<string, HawkCredential> credentials;
        Predicate<HttpRequestMessage> endpointFilter;
        int timeskewInSeconds = 60;

        /// <summary>
        /// Creates a new instance of HawkActionFilter using a type for
        /// instanciating a IHawkCredentialRepository
        /// </summary>
        /// <param name="hawkCredentialRepositoryType">IHawkCredentialRepository type</param>
        public RequiresHawkAttribute(Type hawkCredentialRepositoryType)
            : base()
        {
            if (hawkCredentialRepositoryType == null)
                throw new ArgumentNullException("hawkCredentialRepositoryType");

            if (!hawkCredentialRepositoryType.GetInterfaces()
                .Contains(typeof(IHawkCredentialRepository)))
            {
                throw new ArgumentException(
                    "Must derive from IHawkCredentialRepository", 
                    "hawkCredentialRepositoryType");
            }

            var instance = (IHawkCredentialRepository)Activator
                .CreateInstance(hawkCredentialRepositoryType);

            this.credentials = (id) => instance.Get(id);
        }

        /// <summary>
        /// Creates a new instance of HawkActionFilter using a IHawkCredentialRepository 
        /// implementation
        /// </summary>
        /// <param name="repository">IHawkCredentialRepository implementation</param>
        public RequiresHawkAttribute(IHawkCredentialRepository repository)
            : base()
        {
            if (repository == null)
                throw new ArgumentNullException("repository");

            this.credentials = (id) => repository.Get(id);
        }

        public RequiresHawkAttribute(Func<string, HawkCredential> credentials, Predicate<HttpRequestMessage> endpointFilter = null, int timeskewInSeconds = 60)
            : base()
        {
            if (credentials == null)
                throw new ArgumentNullException("credentials");

            this.credentials = credentials;
            this.endpointFilter = endpointFilter;
            this.timeskewInSeconds = timeskewInSeconds;
        }

        public override void OnAuthorization(System.Web.Http.Controllers.HttpActionContext actionContext)
        {
            IPrincipal principal = null;
            
            var request = actionContext.Request;

            if (this.endpointFilter == null ||
                (this.endpointFilter != null &&
                 this.endpointFilter(actionContext.Request)))
            {
                if (request.Method == HttpMethod.Get &&
                    request.RequestUri != null &&
                    !string.IsNullOrEmpty(request.RequestUri.Query))
                {
                    var query = HttpUtility.ParseQueryString(request.RequestUri.Query);
                    if (query["bewit"] != null)
                    {
                        TraceSource.TraceInformation(string.Format("Bewit found {0}",
                            query["bewit"]));
                        try
                        {
                            principal = request.Authenticate(credentials, this.timeskewInSeconds);
                        }
                        catch (SecurityException ex)
                        {
                            actionContext.Response = ToResponse(
                                request,
                                HttpStatusCode.Unauthorized,
                                ex.Message);

                            return;
                        }

                        Thread.CurrentPrincipal = principal;
                        if (HttpContext.Current != null)
                        {
                            HttpContext.Current.User = principal;
                        }

                        base.OnAuthorization(actionContext);

                        return;
                    }
                }

                if (request.Headers.Authorization == null)
                {
                    actionContext.Response = ChallengeResponse(request);
                }

                if (request.Headers.Authorization != null &&
                    !string.Equals(request.Headers.Authorization.Scheme, Scheme))
                {
                    actionContext.Response = ToResponse(
                        request,
                        HttpStatusCode.Unauthorized,
                        "Only Hawk Supported");

                    return;
                }

                if (request.Headers.Authorization != null &&
                    !string.IsNullOrWhiteSpace(request.Headers.Authorization.Scheme))
                {
                    if (string.IsNullOrWhiteSpace(request.Headers.Authorization.Parameter))
                    {
                        actionContext.Response = ToResponse(
                            request,
                            HttpStatusCode.BadRequest,
                            "Invalid header format");

                        return;
                    }

                    if (string.IsNullOrWhiteSpace(request.Headers.Host))
                    {
                        actionContext.Response = ToResponse(
                            request,
                            HttpStatusCode.BadRequest,
                            "Missing Host header");

                        return;
                    }

                    try
                    {
                        principal = request.Authenticate(credentials, this.timeskewInSeconds);
                    }
                    catch (SecurityException ex)
                    {
                        TraceSource.TraceData(TraceEventType.Error, 0, ex.ToString());

                        actionContext.Response = ToResponse(
                            request,
                            HttpStatusCode.Unauthorized,
                            ex.Message);

                        return;
                    }

                    Thread.CurrentPrincipal = principal;
                    if (HttpContext.Current != null)
                    {
                        HttpContext.Current.User = principal;
                    }
                }
            }

            base.OnAuthorization(actionContext);
        }

        private static HttpResponseMessage ToResponse(HttpRequestMessage request, 
            HttpStatusCode code, string message)
        {
            var response = request.CreateResponse(code);
            response.ReasonPhrase = message;
            response.Content = new StringContent(message);

            return response;
        }

        private static HttpResponseMessage ChallengeResponse(HttpRequestMessage request)
        {
            var ts = Hawk.ConvertToUnixTimestamp(DateTime.Now).ToString();
            var challenge = string.Format("ts=\"{0}\" ntp=\"{1}\"",
                ts, "pool.ntp.org");

            var response = request.CreateResponse(HttpStatusCode.Unauthorized);
            response.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue(Scheme, challenge));

            return response;
        }
    }
}
