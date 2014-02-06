using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin;
using System.Web.Http;
using HawkNet.Owin;
using HawkNet;

namespace Example.Owin
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            var config = new HttpConfiguration();
            config.Routes.MapHttpRoute("Default", "api/{controller}");
            
            app.UseHawkAuthentication(new HawkAuthenticationOptions
            {
                Credentials = (id) =>
                {
                    return Task.FromResult(new HawkCredential
                    {
                        Id = "dh37fgj492je",
                        Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                        Algorithm = "sha256",
                        User = "steve"
                    });
                }
            });
            app.UseWebApi(config);
            
        }
    }
}
