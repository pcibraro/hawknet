using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;
using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HawkNet.Owin
{
    public class HawkAuthenticationMiddleware : AuthenticationMiddleware<HawkAuthenticationOptions>
    {
        private readonly ILogger logger;

        public HawkAuthenticationMiddleware(
            OwinMiddleware next,
            IAppBuilder app,
            HawkAuthenticationOptions options) : base(next, options)
        {
            this.logger = app.CreateLogger<HawkAuthenticationHandler>();
        }

        protected override AuthenticationHandler<HawkAuthenticationOptions> CreateHandler()
        {
            return new HawkAuthenticationHandler(this.logger);
        }
    }
}
