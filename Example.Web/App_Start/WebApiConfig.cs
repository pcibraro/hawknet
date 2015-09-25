using HawkNet.WebApi;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Http;
using HawkNet;
using System.Web.Http.Dispatcher;
using System.Threading.Tasks;

namespace Example.Web
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            config.Routes.MapHttpRoute(
                "DefaultApi",
                "api/{controller}/{id}",
                new { id = RouteParameter.Optional },
                null
            );

            config.Filters.Add(new HawkAuthentication(typeof(HawkCredentialRepository)));
        }
    }

    internal class HawkCredentialRepository : IHawkCredentialRepository
    {
        public Task<HawkCredential> GetCredentialsAsync(string id)
        {
            return Task.FromResult(new HawkCredential
            {
                Id = "dh37fgj492je",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                Algorithm = "sha256",
                User = "steve"
            });
        }
    }
}
