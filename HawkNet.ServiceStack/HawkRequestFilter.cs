using ServiceStack.Common.Web;
using ServiceStack.ServiceHost;
using ServiceStack.ServiceInterface;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Security;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web;

namespace HawkNet.ServiceStack
{
    public class HawkRequestFilter : RequestFilterAttribute, IHasRequestFilter
    {
        static TraceSource TraceSource = new TraceSource("HawkNet");

        const string Scheme = "Hawk";

        Func<string, HawkCredential> credentials;

        /// <summary>
        /// Creates a new instance of HawkActionFilter using a type for
        /// instanciating a IHawkCredentialRepository
        /// </summary>
        /// <param name="hawkCredentialRepositoryType">IHawkCredentialRepository type</param>
        public HawkRequestFilter(Type hawkCredentialRepositoryType)
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
        public HawkRequestFilter(IHawkCredentialRepository repository)
            : base()
        {
            if (repository == null)
                throw new ArgumentNullException("repository");

            this.credentials = (id) => repository.Get(id);
        }

        public HawkRequestFilter(Func<string, HawkCredential> credentials)
            : base()
        {
            if (credentials == null)
                throw new ArgumentNullException("credentials");

            this.credentials = credentials;
        }

        public new int Priority
        {
            // <0 Run before global filters. >=0 Run after
            get { return -1; }
        }

        public override void Execute(IHttpRequest req, IHttpResponse res, object requestDto)
        {
            IPrincipal principal = null;

            var requestUri = new Uri(req.AbsoluteUri);

            if (req.HttpMethod.ToLower() == "get" &&
                !string.IsNullOrEmpty(requestUri.Query))
            {
                var query = HttpUtility.ParseQueryString(requestUri.Query);
                if (query["bewit"] != null)
                {
                    TraceSource.TraceInformation(string.Format("Bewit found {0}",
                        query["bewit"]));
                    try
                    {
                        principal = Hawk.AuthenticateBewit(query["bewit"], req.Headers["Host"], requestUri, this.credentials);
                    }
                    catch (SecurityException ex)
                    {
                        ToResponse(res,
                            HttpStatusCode.Unauthorized,
                            ex.Message);

                        return;
                    }

                    Thread.CurrentPrincipal = principal;
                    if (HttpContext.Current != null)
                    {
                        HttpContext.Current.User = principal;
                    }

                    return;
                }
            }

            if (req.Headers["Authorization"] == null)
            {
                ChallengeResponse(res);
            }

            if (req.Headers["Authorization"] != null &&
                ! req.Headers["Authorization"].StartsWith(Scheme))
            {
                ToResponse(
                    res,
                    HttpStatusCode.Unauthorized,
                    "Only Hawk Supported");

                return;
            }

            if (req.Headers["Authorization"] != null &&
                req.Headers["Authorization"].StartsWith(Scheme))
            {
                var parameter = req.Headers["Authorization"].Replace(Scheme, "")
                    .Trim();

                if (string.IsNullOrEmpty(parameter))
                {
                    ToResponse(
                        res,
                        HttpStatusCode.BadRequest,
                        "Invalid header format");

                    return;
                }

                if (string.IsNullOrEmpty(req.Headers["Host"]))
                {
                    ToResponse(
                        res,
                        HttpStatusCode.BadRequest,
                        "Missing Host header");

                    return;
                }

                try
                {
                    principal = Hawk.Authenticate(parameter, req.Headers["Host"], req.HttpMethod, requestUri, credentials);
                }
                catch (SecurityException ex)
                {
                    TraceSource.TraceData(TraceEventType.Error, 0, ex.ToString());

                    ToResponse(
                        res,
                        HttpStatusCode.Unauthorized,
                        ex.Message);

                    return;
                }

                Thread.CurrentPrincipal = principal;

                return;
            }
            
        }

        private static void ToResponse(IHttpResponse res,
            HttpStatusCode code, string message)
        {
            res.StatusCode = (int)code;
            res.StatusDescription = message;
            res.ContentType = ContentType.PlainText;
            res.Write(message);
            res.Close();
        }

        private static void ChallengeResponse(IHttpResponse response)
        {
            var ts = Hawk.ConvertToUnixTimestamp(DateTime.Now).ToString();
            var challenge = string.Format("ts=\"{0}\" ntp=\"{1}\"",
                ts, "pool.ntp.org");

            response.StatusCode = (int)HttpStatusCode.Unauthorized;
            response.AddHeader("WwwAuthenticate", Scheme + " " + challenge);
        }
    }
}
