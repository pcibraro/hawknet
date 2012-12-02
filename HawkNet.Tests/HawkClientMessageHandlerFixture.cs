using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace HawkNet.Tests
{
    [TestClass]
    public class HawkClientMessageHandlerFixture
    {
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void ShouldFailOnMissingCredentialId()
        {
            var credential = new HawkClientMessageHandler.HawkCredential
            {
                Algorithm = "hmacsha256",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                User = "steve"
            };

            var handler = new HawkClientMessageHandler(new DummyHttpMessageHandler(),
                credential);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void ShouldFailOnMissingCredentialAlgorithm()
        {
            var credential = new HawkClientMessageHandler.HawkCredential
            {
                Id = "123",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                User = "steve"
            };

            var handler = new HawkClientMessageHandler(new DummyHttpMessageHandler(),
                credential);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void ShouldFailOnMissingCredentialKey()
        {
            var credential = new HawkClientMessageHandler.HawkCredential
            {
                Id = "123",
                Algorithm = "hmacsha256",
                User = "steve"
            };

            var handler = new HawkClientMessageHandler(new DummyHttpMessageHandler(),
                credential);
        }

        [TestMethod]
        public void ShouldGenerateAuthHeader()
        {
            var credential = new HawkClientMessageHandler.HawkCredential
            {
                Id = "123",
                Algorithm = "hmacsha256",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                User = "steve"
            };

            var ts = HawkClientMessageHandler.ConvertToUnixTimestamp(DateTime.UtcNow).ToString();

            var handler = new HawkClientMessageHandler(new DummyHttpMessageHandler(),
                credential, "hello", ts);

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Host = "example.com";

            var invoker = new HttpMessageInvoker(handler);
            invoker.SendAsync(request, new CancellationToken());

            var mac = HawkClientMessageHandler.CalculateMac(request, credential, ts, "hello");
            
            var parameter = string.Format("id = \"{0}\", ts = \"{1}\", mac = \"{2}\", ext = \"{3}\"",
                credential.Id, ts, mac, "hello");

            Assert.IsNotNull(request.Headers.Authorization);
            Assert.AreEqual("Hawk", request.Headers.Authorization.Scheme);
            Assert.AreEqual(parameter,
                request.Headers.Authorization.Parameter);
        }

        [TestMethod]
        public void ShouldCalculateMac()
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Host = "example.com";

            var ts = "1353788437";
            var ext = "hello";

            var credential = new HawkClientMessageHandler.HawkCredential
            {
                Id = "123",
                Algorithm = "hmacsha1",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
            };

            var mac = HawkClientMessageHandler.CalculateMac(request, credential, ts, ext);

            Assert.AreEqual("lDdDLlWQhgcxTvYgzzLo3EZExog=", mac);
        }

        [TestMethod]
        public void ShouldCalculateMacWithMissingExt()
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Host = "example.com";

            var ts = "1353788437";

            var credential = new HawkClientMessageHandler.HawkCredential
            {
                Id = "123",
                Algorithm = "hmacsha1",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
            };

            var mac = HawkClientMessageHandler.CalculateMac(request, credential, ts, null);

            Assert.AreEqual("utHS0Jh4n7lwORuDl2Ht3MKHZPU=", mac);
        }

        class DummyHttpMessageHandler : HttpMessageHandler
        {
            protected override System.Threading.Tasks.Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                var tsc = new TaskCompletionSource<HttpResponseMessage>();
                tsc.SetResult(new HttpResponseMessage(HttpStatusCode.OK));

                return tsc.Task;
            }
        }
    }
}
