using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using HawkNet.WebApi;
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
            var credential = new HawkCredential
            {
                Algorithm = "sha256",
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
            var credential = new HawkCredential
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
            var credential = new HawkCredential
            {
                Id = "123",
                Algorithm = "sha256",
                User = "steve"
            };

            var handler = new HawkClientMessageHandler(new DummyHttpMessageHandler(),
                credential);
        }

        [TestMethod]
        public void ShouldGenerateAuthHeader()
        {
            var credential = new HawkCredential
            {
                Id = "123",
                Algorithm = "sha256",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                User = "steve"
            };

            var nonce = "123456";

            var date = DateTime.UtcNow;
            var ts = Hawk.ConvertToUnixTimestamp(date).ToString();

            var handler = new HawkClientMessageHandler(new DummyHttpMessageHandler(),
                credential, "hello", date, nonce);

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");

            var invoker = new HttpMessageInvoker(handler);
            invoker.SendAsync(request, new CancellationToken());

            var mac = Hawk.CalculateMac(request.Headers.Host, request.Method.ToString(), request.RequestUri,
                "hello", ts, nonce, credential, "header");

            var parameter = string.Format("id=\"{0}\", ts=\"{1}\", nonce=\"{2}\", mac=\"{3}\", ext=\"{4}\"",
                credential.Id, ts, nonce, mac, "hello");

            Assert.IsNotNull(request.Headers.Authorization);
            Assert.AreEqual("Hawk", request.Headers.Authorization.Scheme);
            Assert.AreEqual(parameter,
                request.Headers.Authorization.Parameter);
        }

        [TestMethod]
        public void ShouldGenerateAuthHeaderWithPayloadHash()
        {
            var credential = new HawkCredential
            {
                Id = "123",
                Algorithm = "sha256",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                User = "steve"
            };

            var payload = "foo";

            var hmac = System.Security.Cryptography.HMAC.Create(credential.Algorithm);
            hmac.Key = Encoding.ASCII.GetBytes(credential.Key);

            var payloadHash = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(payload)));

            var nonce = Hawk.GetRandomString(6);

            var date = DateTime.UtcNow;
            var ts = Hawk.ConvertToUnixTimestamp(date).ToString();

            var handler = new HawkClientMessageHandler(new DummyHttpMessageHandler(),
                credential, "hello", date, nonce, true);

            var request = new HttpRequestMessage(HttpMethod.Post, "http://example.com:8080/resource/4?filter=a");
            request.Content = new StringContent(payload);

            var invoker = new HttpMessageInvoker(handler);
            var response = invoker.SendAsync(request, new CancellationToken());

            var mac = Hawk.CalculateMac(request.Headers.Host, request.Method.ToString(), request.RequestUri,
                "hello", ts, nonce, credential, "header", payloadHash);

            var parameter = string.Format("id=\"{0}\", ts=\"{1}\", nonce=\"{2}\", mac=\"{3}\", ext=\"{4}\", hash=\"{5}\"",
                credential.Id, ts, nonce, mac, "hello", payloadHash);

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
            var nonce = "123456";

            var credential = new HawkCredential
            {
                Id = "123",
                Algorithm = "sha1",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
            };

            var mac = Hawk.CalculateMac(request.Headers.Host, request.Method.ToString(), request.RequestUri, 
                ext, ts, nonce, credential, "header");

            Assert.AreEqual("AJhfGJR+mEVOISNMDUIeLr9ONgc=", mac);
        }

        [TestMethod]
        public void ShouldCalculateMacWithMissingExt()
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");

            var ts = "1353788437";
            var nonce = "123456";

            var credential = new HawkCredential
            {
                Id = "123",
                Algorithm = "sha1",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
            };

            var mac = Hawk.CalculateMac("example.com", "Get", new Uri("http://example.com:8080/resource/4?filter=a"),
                null, ts, nonce, credential, "header");

            Assert.AreEqual("xzewml0eeTU60IbA45JAj/9GbuY=", mac);
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