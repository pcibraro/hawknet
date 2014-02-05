using HawkNet;
using HawkNet.WebApi;
using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Dispatcher;

namespace Example
{
    public class Startup
    {
        // This code configures Web API. The Startup class is specified as a type
        // parameter in the WebApp.Start method.
        public void Configuration(IAppBuilder appBuilder)
        {
            // Configure Web API for self-host. 
            HttpConfiguration config = new HttpConfiguration();
            
            var handler = new HawkMessageHandler(new HttpControllerDispatcher(config),
               (id) =>
               {
                   return Task.FromResult(new HawkCredential
                   {
                       Id = id,
                       Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                       Algorithm = "hmacsha256",
                       User = "steve"
                   });
               });

            config.Routes.MapHttpRoute(
                "Filter", "api/filter",
                new
                {
                    controller = "HelloWorldWithFilter"
                });

            config.Routes.MapHttpRoute(
                "API Default", "api/{controller}/{id}",
                new
                {
                    id = RouteParameter.Optional,
                    controller = "HelloWorld"
                },
                null,
                handler
            );

            appBuilder.UseWebApi(config);
        }
    } 
}
