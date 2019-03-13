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
                AuthenticationHeaderValue.TryParse(Request.Headers["authorization"], out authorization);
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

                Func<Task<string>> requestPayload = (async () =>
                {
                    var requestBuffer = new MemoryStream();
                    await Request.Body.CopyToAsync(requestBuffer).ConfigureAwait(false);
                    requestBuffer.Flush();

                    Request.Body = requestBuffer;

                    var payload = Encoding.UTF8.GetString(requestBuffer.ToArray());
                    
                    return payload;
                });

                try
                {
                    var principal = await Hawk.AuthenticateAsync(authorization.Parameter,
                            Request.Host.Value,
                            Request.Method,
                            Request.Uri,
                            this.Options.Credentials,
                            this.Options.TimeskewInSeconds,
                            requestPayload,
                            Request.ContentType);

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

        public override Task<bool> InvokeAsync()
        {
            if (this.Options.IncludeServerAuthorization)
            {
                Response.Body = new StreamWrapper(Response.Body);
            }

            return base.InvokeAsync();
        }

        protected override async Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode == 200)
            {
                if (this.Options.IncludeServerAuthorization)
                {
                    AuthenticationHeaderValue authorization;
                    if (AuthenticationHeaderValue.TryParse(Request.Headers["authorization"], out authorization)
                        && authorization.Scheme.Equals(HawkAuthenticationOptions.Scheme, StringComparison.OrdinalIgnoreCase))
                    {
                        await AuthenticateResponse(authorization.Parameter,
                                Request.Host.Value,
                                Request.Method,
                                Request.Uri,
                                Response.ContentType,
                                this.Options.Credentials,
                                Response);
                    }
                }
            }
            else if (Response.StatusCode == 401)
            {
                var ts = Hawk.ConvertToUnixTimestamp(DateTime.Now).ToString();
                var challenge = string.Format("ts=\"{0}\" ntp=\"{1}\"",
                        ts, "pool.ntp.org");

                Response.Headers.Append("WWW-Authenticate", HawkAuthenticationOptions.Scheme + " " + challenge);
            }
        }

        private async Task AuthenticateResponse(string authorization,
            string host,
            string method,
            Uri uri,
            string mediaType,
            Func<string, Task<HawkCredential>> credentials,
            IOwinResponse response)
        {
            var attributes = Hawk.ParseAttributes(authorization);

            var credential = await credentials(attributes["id"]);

            response.Body.Seek(0, SeekOrigin.Begin);

            var payload = Encoding.UTF8.GetString(((StreamWrapper)response.Body).ToArray());

            var hash = Hawk.CalculatePayloadHash(payload, response.ContentType, credential);

            var mac = Hawk.CalculateMac(host,
                method,
                uri,
                null,
                attributes["ts"],
                attributes["nonce"],
                credential,
                "response",
                hash);

            var serverAuthorization = string.Format("mac=\"{0}\", hash=\"{1}\"",
                    mac, hash);

            response.Headers.Add("Server-Authorization", new string[] { "Hawk " + serverAuthorization });
        }

        private static DateTime UnixTimeStampToDateTime(double unixTimeStamp)
        {
            // Unix timestamp is seconds past epoch
            var datetime = new DateTime(1970, 1, 1, 0, 0, 0, 0);
            datetime = datetime.AddSeconds(unixTimeStamp).ToLocalTime();
            return datetime;
        }

        private static AuthenticationTicket EmptyTicket()
        {
            return new AuthenticationTicket(null, null);
        }
    }
}
