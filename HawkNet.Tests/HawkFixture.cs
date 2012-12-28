using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace HawkNet.Tests
{
    [TestClass]
    public class HawkFixture
    {
        const string ValidAuthorization = "id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"lDdDLlWQhgcxTvYgzzLo3EZExog=\", ext=\"hello\"";

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void ShouldFailAuthenticationOnNullAuthorization()
        {
            Hawk.Authenticate(null, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), GetCredential);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void ShouldFailAuthenticationOnEmptyAuthorization()
        {
            Hawk.Authenticate(" ", "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), GetCredential);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void ShouldFailAuthenticationOnNullHost()
        {
            Hawk.Authenticate(ValidAuthorization, null, "get", new Uri("http://example.com:8080/resource/4?filter=a"), GetCredential);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void ShouldFailAuthenticationOnEmptyHost()
        {
            Hawk.Authenticate(ValidAuthorization, " ", "get", new Uri("http://example.com:8080/resource/4?filter=a"), GetCredential);
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException), "Missing credentials")]
        public void ShouldFailAuthenticationOnNullCredential()
        {
            Hawk.Authenticate(ValidAuthorization, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), (s) => null);
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException), "Missing attributes")]
        public void ShouldFailAuthenticationOnMissingAuthAttribute()
        {
            Hawk.Authenticate("ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\"",
                "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), GetCredential);
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException), "Missing attributes")]
        public void ShouldFailAuthenticationOnUnknownAuthAttribute()
        {
            Hawk.Authenticate("id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", x=\"3\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\"",
                "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), GetCredential);
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException), "Invalid credentials")]
        public void ShouldFailAuthenticationOnMissingCredentialAlgorithm()
        {
            var credential = new HawkCredential
            {
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                User = "steve"
            };

            Hawk.Authenticate(ValidAuthorization, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), (s) => credential);
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException), "Invalid credentials")]
        public void ShouldFailAuthenticationOnMissingCredentialKey()
        {
            var credential = new HawkCredential
            {
                Algorithm = "hmacsha1",
                User = "steve"
            };

            Hawk.Authenticate(ValidAuthorization, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), (s) => credential);
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException), "Unknown algorithm")]
        public void ShouldFailAuthenticationOnUnknownCredentialAlgorithm()
        {
            var credential = new HawkCredential
            {
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                Algorithm = "foo",
                User = "steve"
            };

            Hawk.Authenticate(ValidAuthorization, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), (s) => credential);
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException), "Bad mac")]
        public void ShouldFailAuthenticationOnInvalidMac()
        {
            var authorization = "id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"lDdDLlWQhgcxTvYgzzLo3EZExogXXXX=\", ext=\"hello\"";
            Hawk.Authenticate(authorization, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), GetCredential);
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

            var authorization = "id=\"456\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"qrP6b5tiS2CO330rpjUEym/USBM=\", ext=\"hello\"";
            var principal = Hawk.Authenticate(authorization, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), (s) => credential);

            Assert.IsNotNull(principal);
            Assert.IsInstanceOfType(principal, typeof(ClaimsPrincipal));
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

            var authorization = "id=\"456\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"ZPa2zWC3WUAYXrwPzJ3DpF54xjQ2ZDLe8GF1ny6JJFI=\", ext=\"hello\"";
            var principal = Hawk.Authenticate(authorization, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), (s) => credential);

            Assert.IsNotNull(principal);
            Assert.IsInstanceOfType(principal, typeof(ClaimsPrincipal));
        }

        [TestMethod]
        public void ShouldCalculateMac()
        {
            var credential = new HawkCredential
            {
                Algorithm = "hmacsha1",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
            };

            var mac = Hawk.CalculateMac("example.com", "Get", 
                new Uri("http://example.com:8080/resource/4?filter=a"), "hello", "1353788437", Hawk.GetRandomString(6), credential);

            Assert.AreEqual("W2uv8gVKBomRuYSaTiIbhGvF8Ws=", mac);
        }

        [TestMethod]
        public void ShouldCalculateMacWithMissingExt()
        {
            var credential = new HawkCredential
            {
                Algorithm = "hmacsha1",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
            };

            var mac = Hawk.CalculateMac("example.com", "Get", new Uri("http://example.com:8080/resource/4?filter=a"),
                null, "1353788437", Hawk.GetRandomString(6), credential);

            Assert.AreEqual("OZL011pWkK+SfO70XhFGAuo9Sv0=", mac);
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
