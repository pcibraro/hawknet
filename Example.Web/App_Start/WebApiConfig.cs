using HawkNet.WebApi;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Http;
using HawkNet;

namespace Example.Web
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            config.Filters.Add(new RequiresHawkAttribute((id) =>
                {
                    return new HawkCredential
                    {
                        Id = "dh37fgj492je",
                        Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                        Algorithm = "hmacsha256",
                        User = "steve"
                    };
                }));

            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );
        }
    }
}
