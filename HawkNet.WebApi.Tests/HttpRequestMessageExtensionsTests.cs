using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace HawkNet.Tests
{
    [TestClass]
    public class HttpRequestMessageExtensionsTests
    {
        [TestMethod]
        public void ShouldSignRequest()
        {
            var credential = new HawkCredential
            {
                Id = "456",
                Algorithm = "sha256",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                User = "steve"
            };

            var date = DateTime.Now;

            var ts = Hawk.ConvertToUnixTimestamp(date);
            var mac = Hawk.CalculateMac("example.com:8080", "get", new Uri("http://example.com:8080/resource/4?filter=a"), "hello", ts.ToString(), "k3j4h2", credential, "header");

            var authorization = string.Format("id=\"456\", ts=\"{0}\", nonce=\"k3j4h2\", mac=\"{1}\", ext=\"hello\"",
                ts, mac);

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.SignRequest(credential, "hello", date, "k3j4h2", null);

            Assert.IsNotNull(request.Headers.Authorization != null);
            Assert.AreEqual(request.Headers.Authorization.Scheme, "Hawk");
            Assert.AreEqual(request.Headers.Authorization.Parameter, authorization);
        }

        [TestMethod]
        public void ShouldAuthenticateRequest()
        {
            var credential = new HawkCredential
            {
                Id = "456",
                Algorithm = "sha256",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                User = "steve"
            };

            var date = DateTime.Now;

            var ts = Hawk.ConvertToUnixTimestamp(date);
            var mac = Hawk.CalculateMac("example.com:8080", "get", new Uri("http://example.com:8080/resource/4?filter=a"), "hello", ts.ToString(), "k3j4h2", credential, "header");

            var authorization = string.Format("id=\"456\", ts=\"{0}\", nonce=\"k3j4h2\", mac=\"{1}\", ext=\"hello\"",
                ts, mac);

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Host = "example.com:8080";
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Hawk", authorization);

            var principal = request.AuthenticateAsync((id) => Task.FromResult(credential));

            Assert.IsNotNull(principal);
        }
    }
}
