using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;

namespace HawkNet.WebApi.Tests
{
    [TestClass]
    public class RequiresHawkAttributeTests
    {
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void ShouldThrowIfRepositoryTypeIsNull()
        {
            new RequiresHawkAttribute((Type)null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void ShoulThrowWhenInvalidRepositoryType()
        {
            var filter = new RequiresHawkAttribute(typeof(object));
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void ShouldThrowIfRepositoryIsNull()
        {
            new RequiresHawkAttribute((IHawkCredentialRepository)null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void ShouldThrowIfFuncDelegateIsNull()
        {
            new RequiresHawkAttribute((Func<string, HawkCredential>)null);
        }

        [TestMethod]
        public void ShouldNotAuthorizeOnWrongAuthScheme()
        {
            var filter = new RequiresHawkAttribute(GetCredential);

            var request = new HttpRequestMessage(HttpMethod.Get, 
                "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic");

            var context = new HttpActionContext();
            context.ControllerContext = new HttpControllerContext();
            context.ControllerContext.Request = request;

            filter.OnAuthorization(context);

            Assert.IsNotNull(context.Response);
            Assert.AreEqual(HttpStatusCode.Unauthorized, context.Response.StatusCode);
        }

        [TestMethod]
        public void ShouldFailOnWMissingHostHeader()
        {
            var filter = new RequiresHawkAttribute(GetCredential);

            var request = new HttpRequestMessage();
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", "id = \"123\", ts = \"1353788437\", mac = \"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext = \"hello\"");

            var context = new HttpActionContext();
            context.ControllerContext = new HttpControllerContext();
            context.ControllerContext.Request = request;

            filter.OnAuthorization(context);

            Assert.AreEqual(HttpStatusCode.BadRequest, context.Response.StatusCode);
            Assert.AreEqual("Missing Host header", context.Response.ReasonPhrase);
        }

        [TestMethod]
        public void ShouldFailOnMissingAuthAttribute()
        {
            var filter = new RequiresHawkAttribute(GetCredential);

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", "ts = \"1353788437\", mac = \"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext = \"hello\"");
            request.Headers.Host = "localhost";

            var context = new HttpActionContext();
            context.ControllerContext = new HttpControllerContext();
            context.ControllerContext.Request = request;

            filter.OnAuthorization(context);

            Assert.AreEqual(HttpStatusCode.Unauthorized, context.Response.StatusCode);
            Assert.AreEqual("Missing attributes", context.Response.ReasonPhrase);
        }

        [TestMethod]
        public void ShouldFailOnUnknownAuthAttribute()
        {
            var filter = new RequiresHawkAttribute(GetCredential);

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", "id = \"123\", ts = \"1353788437\", nonce = \"1353788437\", x = \"3\", mac = \"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext = \"hello\"");
            request.Headers.Host = "localhost";

            var context = new HttpActionContext();
            context.ControllerContext = new HttpControllerContext();
            context.ControllerContext.Request = request;

            filter.OnAuthorization(context);

            Assert.AreEqual(HttpStatusCode.Unauthorized, context.Response.StatusCode);
            Assert.AreEqual("Unknown attributes", context.Response.ReasonPhrase);
        }

        [TestMethod]
        public void ShouldFailOnInvalidAuthFormat()
        {
            var filter = new RequiresHawkAttribute(GetCredential);

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", "");
            request.Headers.Host = "localhost";

            var context = new HttpActionContext();
            context.ControllerContext = new HttpControllerContext();
            context.ControllerContext.Request = request;

            filter.OnAuthorization(context);

            Assert.AreEqual(HttpStatusCode.BadRequest, context.Response.StatusCode);
            Assert.AreEqual("Invalid header format", context.Response.ReasonPhrase);
        }

        [TestMethod]
        public void ShouldFailOnCredentialsFuncException()
        {
            var filter = new RequiresHawkAttribute((id) => { throw new Exception("Invalid"); });

            var ts = Math.Floor(Hawk.ConvertToUnixTimestamp(DateTime.Now) / 1000).ToString();

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", "id = \"456\", ts = \"" + ts + "\", nonce=\"k3j4h2\", mac = \"qrP6b5tiS2CO330rpjUEym/USBM=\", ext = \"hello\"");
            request.Headers.Host = "localhost";

            var context = new HttpActionContext();
            context.ControllerContext = new HttpControllerContext();
            context.ControllerContext.Request = request;

            filter.OnAuthorization(context);

            Assert.AreEqual(HttpStatusCode.Unauthorized, context.Response.StatusCode);
            Assert.AreEqual("Unknown user", context.Response.ReasonPhrase);
        }

        [TestMethod]
        public void ShouldFailOnMissingCredentials()
        {
            var filter = new RequiresHawkAttribute((id) => { return null; });

            var ts = Math.Floor(Hawk.ConvertToUnixTimestamp(DateTime.Now) / 1000).ToString();

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", "id = \"456\", ts = \"" + ts + "\", nonce=\"k3j4h2\", mac = \"qrP6b5tiS2CO330rpjUEym/USBM=\", ext = \"hello\"");
            request.Headers.Host = "localhost";

            var context = new HttpActionContext();
            context.ControllerContext = new HttpControllerContext();
            context.ControllerContext.Request = request;

            filter.OnAuthorization(context);

            Assert.AreEqual(HttpStatusCode.Unauthorized, context.Response.StatusCode);
            Assert.AreEqual("Missing credentials", context.Response.ReasonPhrase);
        }

        [TestMethod]
        public void ShouldFailOnInvalidCredentials()
        {
            var filter = new RequiresHawkAttribute((id) =>
            {
                return new HawkCredential
                {
                    Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                    User = "steve"
                };
            });

            var ts = Math.Floor(Hawk.ConvertToUnixTimestamp(DateTime.Now) / 1000).ToString();

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", "id = \"456\", ts = \"" + ts + "\", nonce=\"k3j4h2\", mac = \"qrP6b5tiS2CO330rpjUEym/USBM=\", ext = \"hello\"");
            request.Headers.Host = "localhost";

            var context = new HttpActionContext();
            context.ControllerContext = new HttpControllerContext();
            context.ControllerContext.Request = request;

            filter.OnAuthorization(context);

            Assert.AreEqual(HttpStatusCode.Unauthorized, context.Response.StatusCode);
            Assert.AreEqual("Invalid credentials", context.Response.ReasonPhrase);
        }

        [TestMethod]
        public void ShouldFailOnUnknownCredentialsAlgorithm()
        {
            var filter = new RequiresHawkAttribute((id) =>
            {
                return new HawkCredential
                {
                    Id = "123",
                    Algorithm = "hmac-sha-0",
                    Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                    User = "steve"
                };
            });

            var ts = Math.Floor(Hawk.ConvertToUnixTimestamp(DateTime.Now) / 1000).ToString();

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", "id = \"456\", ts = \"" + ts + "\", nonce=\"k3j4h2\", mac = \"qrP6b5tiS2CO330rpjUEym/USBM=\", ext = \"hello\"");
            request.Headers.Host = "localhost";

            var context = new HttpActionContext();
            context.ControllerContext = new HttpControllerContext();
            context.ControllerContext.Request = request;

            filter.OnAuthorization(context);

            Assert.AreEqual(HttpStatusCode.Unauthorized, context.Response.StatusCode);
            Assert.AreEqual("Unknown algorithm", context.Response.ReasonPhrase);
        }

        [TestMethod]
        public void ShouldFailOnUnknownBadMac()
        {
            var filter = new RequiresHawkAttribute((id) =>
            {
                return new HawkCredential
                {
                    Id = "123",
                    Algorithm = "hmacsha256",
                    Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                    User = "steve"
                };
            });

            var ts = Math.Floor(Hawk.ConvertToUnixTimestamp(DateTime.Now) / 1000).ToString();

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", "id = \"456\", ts = \"" + ts + "\", nonce=\"k3j4h2\", mac = \"/qwS4UjfVWMcU4jlr7T/wuKe3dKijvTvSos=\", ext = \"hello\"");
            request.Headers.Host = "localhost";

            var context = new HttpActionContext();
            context.ControllerContext = new HttpControllerContext();
            context.ControllerContext.Request = request;

            filter.OnAuthorization(context);

            Assert.AreEqual(HttpStatusCode.Unauthorized, context.Response.StatusCode);
            Assert.AreEqual("Bad mac", context.Response.ReasonPhrase);
        }

        [TestMethod]
        public void ShouldReturnChallengeOnEmptyAuthHeaderWithStatusUnauthorized()
        {
            var filter = new RequiresHawkAttribute((id) =>
            {
                return new HawkCredential
                {
                    Id = "123",
                    Algorithm = "hmac-sha-0",
                    Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                    User = "steve"
                };
            });

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Host = "localhost";

            var context = new HttpActionContext();
            context.ControllerContext = new HttpControllerContext();
            context.ControllerContext.Request = request;
            context.Response = new HttpResponseMessage(HttpStatusCode.Unauthorized);

            filter.OnAuthorization(context);

            Assert.AreEqual(HttpStatusCode.Unauthorized, context.Response.StatusCode);
            Assert.IsTrue(context.Response.Headers.WwwAuthenticate.Any(h => h.Scheme == "Hawk"));
        }

        [TestMethod]
        public void ShouldParseValidAuthHeaderWithSha1()
        {
            var credential = new HawkCredential
            {
                Id = "123",
                Algorithm = "hmacsha1",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                User = "steve"
            };

            var filter = new RequiresHawkAttribute((id) =>
            {
                return credential;
            });

            var ts = Math.Floor(Hawk.ConvertToUnixTimestamp(DateTime.Now) / 1000);
            var mac = Hawk.CalculateMac("example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), "hello", ts.ToString(), "j4h3g2", credential, "header");

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", string.Format("id = \"456\", ts = \"{0}\", nonce=\"j4h3g2\", mac = \"{1}\", ext = \"hello\"",
                ts, mac));

            request.Headers.Host = "example.com";

            var context = new HttpActionContext();
            context.ControllerContext = new HttpControllerContext();
            context.ControllerContext.Request = request;

            filter.OnAuthorization(context);

            Assert.AreEqual(Thread.CurrentPrincipal.GetType(), typeof(ClaimsPrincipal));
        }

        [TestMethod]
        public void ShouldParseValidBewit()
        {
            var credential = new HawkCredential
            {
                Id = "123",
                Algorithm = "hmacsha256",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                User = "steve"
            };

            var filter = new RequiresHawkAttribute((id) =>
            {
                return credential;
            });

            var bewit = Hawk.GetBewit("example.com", new Uri("http://example.com:8080/resource/4?filter=a"), credential, 1000);

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a&bewit=" + bewit);
            request.Headers.Host = "example.com";

            var context = new HttpActionContext();
            context.ControllerContext = new HttpControllerContext();
            context.ControllerContext.Request = request;

            filter.OnAuthorization(context);

            Assert.AreEqual(Thread.CurrentPrincipal.GetType(), typeof(ClaimsPrincipal));
        }

        [TestMethod]
        public void ShouldParseValidAuthHeaderWithSha256()
        {
            var credential = new HawkCredential
            {
                Id = "123",
                Algorithm = "hmacsha256",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                User = "steve"
            };

            var filter = new RequiresHawkAttribute((id) =>
            {
                return credential;
            });

            var ts = Math.Floor(Hawk.ConvertToUnixTimestamp(DateTime.Now) / 1000);
            var mac = Hawk.CalculateMac("example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), "hello", ts.ToString(), "j4h3g2", credential, "header");

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", string.Format("id = \"456\", ts = \"{0}\", nonce=\"j4h3g2\", mac = \"{1}\", ext = \"hello\"",
                ts, mac));

            request.Headers.Host = "example.com";

            var context = new HttpActionContext();
            context.ControllerContext = new HttpControllerContext();
            context.ControllerContext.Request = request;

            filter.OnAuthorization(context);

            Assert.AreEqual(Thread.CurrentPrincipal.GetType(), typeof(ClaimsPrincipal));
        }

        [TestMethod]
        public void ShouldSkipAuthenticationForEndpoint()
        {
            var filter = new RequiresHawkAttribute((id) =>
            {
                return new HawkCredential
                {
                    Id = "123",
                    Algorithm = "hmac-sha-0",
                    Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                    User = "steve"
                };
            }, (r) => !r.RequestUri.AbsoluteUri.EndsWith("$metadata"));

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/$metadata");

            var context = new HttpActionContext();
            context.ControllerContext = new HttpControllerContext();
            context.ControllerContext.Request = request;

            filter.OnAuthorization(context);

            Assert.IsNull(context.Response);
        }

        private HawkCredential GetCredential(string id)
        {
            return new HawkCredential
            {
                Id = id,
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                Algorithm = (id == "1" ? "hmacsha1" : "hmacsha256"),
                User = "steve"
            };
        }
    }
}
