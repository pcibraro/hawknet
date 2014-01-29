using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Security;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Microsoft.Owin;

namespace HawkNet.Owin
{
    public class HawkAuthenticationHandler : AuthenticationHandler<HawkAuthenticationOptions>
    {
        private readonly ILogger logger;

        public HawkAuthenticationHandler(ILogger logger)
        {
            this.logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            if (Request.Method.Equals("get", StringComparison.InvariantCultureIgnoreCase) &&
                !string.IsNullOrEmpty(Request.Uri.Query))
            {
                var query = HttpUtility.ParseQueryString(Request.Uri.Query);
                if (query["bewit"] != null)
                {
                    this.logger.WriteInformation(string.Format("Bewit found {0}",
                        query["bewit"]));
                    try
                    {
                        var principal = await Hawk.AuthenticateBewitAsync(query["bewit"],
                            Request.Host.Value,
                            Request.Uri,
                            this.Options.Credentials);

                        var identity = (ClaimsIdentity)((ClaimsPrincipal)principal).Identity;
                        var ticket = new AuthenticationTicket(identity, null);

                        return ticket;

                    }
                    catch (SecurityException ex)
                    {
                        this.logger.WriteWarning("Unauthorized call. " + ex.Message);
                        
                        return EmptyTicket();
                    }
                }
            }

            AuthenticationHeaderValue authorization = null;

            if (Request.Headers.ContainsKey("authorization"))
            {
                authorization = AuthenticationHeaderValue.Parse(Request.Headers["authorization"]);
            }

             if (authorization != null &&
                !string.Equals(authorization.Scheme, HawkAuthenticationOptions.Scheme))
             {
                 this.logger.WriteInformation(string.Format("Authorization skipped. Schema found {0}",
                         authorization.Scheme));

                 return EmptyTicket();
             }

            if (authorization == null ||
                string.IsNullOrWhiteSpace(authorization.Scheme))
            {
                this.logger.WriteWarning("Authorization header not found");

                return EmptyTicket();
            }
            else
            {
                if (string.IsNullOrWhiteSpace(authorization.Parameter))
                {
                    this.logger.WriteWarning("Invalid header format");
                    
                    return EmptyTicket();
                }

                if (string.IsNullOrWhiteSpace(Request.Host.Value))
                {
                    this.logger.WriteWarning("Missing Host header");
                    
                    return EmptyTicket();
                }

                try
                {
                    var principal = await Hawk.AuthenticateAsync(authorization.Parameter,
                            Request.Host.Value,
                            Request.Method,
                            Request.Uri,
                            this.Options.Credentials);

                    var identity = (ClaimsIdentity)((ClaimsPrincipal)principal).Identity;
                    var ticket = new AuthenticationTicket(identity, null);

                    return ticket;
                }
                catch (SecurityException ex)
                {
                    this.logger.WriteWarning(ex.Message);

                    return EmptyTicket();
                }
            }
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            var ts = Hawk.ConvertToUnixTimestamp(DateTime.Now).ToString();
            var challenge = string.Format("ts=\"{0}\" ntp=\"{1}\"",
                    ts, "pool.ntp.org");

            Response.Headers.Append("WWW-Authenticate", HawkAuthenticationOptions.Scheme + " " + challenge);
            
            return Task.FromResult<object>(null);
        }

        private static AuthenticationTicket EmptyTicket()
        {
            return new AuthenticationTicket(null, null);
        }
    }
}
