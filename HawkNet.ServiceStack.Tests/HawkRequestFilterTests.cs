using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using ServiceStack.ServiceHost;
using System.Collections.Specialized;
using System.Net;
using System.Threading;

namespace HawkNet.ServiceStack.Tests
{
    [TestClass]
    public class HawkRequestFilterTests
    {
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void ShouldThrowIfRepositoryTypeIsNull()
        {
            new HawkRequestFilter((Type)null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void ShoulThrowWhenInvalidRepositoryType()
        {
            var filter = new HawkRequestFilter(typeof(object));
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void ShouldThrowIfRepositoryIsNull()
        {
            new HawkRequestFilter((IHawkCredentialRepository)null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void ShouldThrowIfFuncDelegateIsNull()
        {
            new HawkRequestFilter((Func<string, HawkCredential>)null);
        }

        [TestMethod]
        public void ShouldNotAuthorizeOnWrongAuthScheme()
        {
            var filter = new HawkRequestFilter(GetCredential);

            var headers = new NameValueCollection();

            var request = new Mock<IHttpRequest>();
            request.SetupGet(r => r.AbsoluteUri).Returns("http://example.com:8080/resource/4?filter=a");
            request.SetupGet(r => r.HttpMethod).Returns("GET");
            request.SetupGet(r => r.Headers).Returns(headers);

            headers.Add("Authorization", "Basic ");

            var response = new Mock<IHttpResponse>();

            filter.Execute(request.Object, response.Object, new object());

            response.VerifySet(r => r.StatusCode = 401);
        }

        [TestMethod]
        public void ShouldFailOnWMissingHostHeader()
        {
            var filter = new HawkRequestFilter(GetCredential);

            var headers = new NameValueCollection();

            var request = new Mock<IHttpRequest>();
            request.SetupGet(r => r.AbsoluteUri).Returns("http://example.com:8080/resource/4?filter=a");
            request.SetupGet(r => r.HttpMethod).Returns("GET");
            request.SetupGet(r => r.Headers).Returns(headers);

            headers.Add("Authorization", "Hawk id = \"123\", ts = \"1353788437\", mac = \"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext = \"hello\"");

            var response = new Mock<IHttpResponse>();

            filter.Execute(request.Object, response.Object, new object());

            response.VerifySet(r => r.StatusCode = (int)HttpStatusCode.BadRequest);
            response.VerifySet(r => r.StatusDescription = "Missing Host header");
        }

        [TestMethod]
        public void ShouldFailOnMissingAuthAttribute()
        {
            var filter = new HawkRequestFilter(GetCredential);

            var headers = new NameValueCollection();

            var request = new Mock<IHttpRequest>();
            request.SetupGet(r => r.AbsoluteUri).Returns("http://example.com:8080/resource/4?filter=a");
            request.SetupGet(r => r.HttpMethod).Returns("GET");
            request.SetupGet(r => r.Headers).Returns(headers);

            headers.Add("Host", "localhost");
            headers.Add("Authorization", "Hawk ts = \"1353788437\", mac = \"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext = \"hello\"");

            var response = new Mock<IHttpResponse>();

            filter.Execute(request.Object, response.Object, new object());

            response.VerifySet(r => r.StatusCode = (int)HttpStatusCode.Unauthorized);
            response.VerifySet(r => r.StatusDescription = "Missing attributes");
        }

        [TestMethod]
        public void ShouldFailOnUnknownAuthAttribute()
        {
            var filter = new HawkRequestFilter(GetCredential);

            var headers = new NameValueCollection();

            var request = new Mock<IHttpRequest>();
            request.SetupGet(r => r.AbsoluteUri).Returns("http://example.com:8080/resource/4?filter=a");
            request.SetupGet(r => r.HttpMethod).Returns("GET");
            request.SetupGet(r => r.Headers).Returns(headers);

            headers.Add("Host", "localhost");
            headers.Add("Authorization", "Hawk id = \"123\", ts = \"1353788437\", nonce = \"1353788437\", x = \"3\", mac = \"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext = \"hello\"");

            var response = new Mock<IHttpResponse>();

            filter.Execute(request.Object, response.Object, new object());

            response.VerifySet(r => r.StatusCode = (int)HttpStatusCode.Unauthorized);
            response.VerifySet(r => r.StatusDescription = "Unknown attributes");
        }

        [TestMethod]
        public void ShouldFailOnInvalidAuthFormat()
        {
            var filter = new HawkRequestFilter(GetCredential);

            var headers = new NameValueCollection();

            var request = new Mock<IHttpRequest>();
            request.SetupGet(r => r.AbsoluteUri).Returns("http://example.com:8080/resource/4?filter=a");
            request.SetupGet(r => r.HttpMethod).Returns("GET");
            request.SetupGet(r => r.Headers).Returns(headers);

            headers.Add("Host", "localhost");
            headers.Add("Authorization", "Hawk ");

            var response = new Mock<IHttpResponse>();

            filter.Execute(request.Object, response.Object, new object());

            response.VerifySet(r => r.StatusCode = (int)HttpStatusCode.BadRequest);
            response.VerifySet(r => r.StatusDescription = "Invalid header format");
        }

        [TestMethod]
        public void ShouldFailOnCredentialsFuncException()
        {
            var filter = new HawkRequestFilter((id) => { throw new Exception("Invalid"); });

            var ts = Math.Floor(Hawk.ConvertToUnixTimestamp(DateTime.Now) / 1000).ToString();

            var headers = new NameValueCollection();

            var request = new Mock<IHttpRequest>();
            request.SetupGet(r => r.AbsoluteUri).Returns("http://example.com:8080/resource/4?filter=a");
            request.SetupGet(r => r.HttpMethod).Returns("GET");
            request.SetupGet(r => r.Headers).Returns(headers);

            headers.Add("Host", "localhost");
            headers.Add("Authorization", "Hawk id = \"456\", ts = \"" + ts + "\", nonce=\"k3j4h2\", mac = \"qrP6b5tiS2CO330rpjUEym/USBM=\", ext = \"hello\"");

            var response = new Mock<IHttpResponse>();

            filter.Execute(request.Object, response.Object, new object());

            response.VerifySet(r => r.StatusCode = (int)HttpStatusCode.Unauthorized);
            response.VerifySet(r => r.StatusDescription = "Unknown user");
        }

        [TestMethod]
        public void ShouldFailOnMissingCredentials()
        {
            var filter = new HawkRequestFilter((id) => { return null; });

            var ts = Math.Floor(Hawk.ConvertToUnixTimestamp(DateTime.Now) / 1000).ToString();

            var headers = new NameValueCollection();

            var request = new Mock<IHttpRequest>();
            request.SetupGet(r => r.AbsoluteUri).Returns("http://example.com:8080/resource/4?filter=a");
            request.SetupGet(r => r.HttpMethod).Returns("GET");
            request.SetupGet(r => r.Headers).Returns(headers);

            headers.Add("Host", "localhost");
            headers.Add("Authorization", "Hawk id = \"456\", ts = \"" + ts + "\", nonce=\"k3j4h2\", mac = \"qrP6b5tiS2CO330rpjUEym/USBM=\", ext = \"hello\"");

            var response = new Mock<IHttpResponse>();

            filter.Execute(request.Object, response.Object, new object());

            response.VerifySet(r => r.StatusCode = (int)HttpStatusCode.Unauthorized);
            response.VerifySet(r => r.StatusDescription = "Missing credentials");
        }

        [TestMethod]
        public void ShouldFailOnInvalidCredentials()
        {
            var filter = new HawkRequestFilter((id) =>
            {
                return new HawkCredential
                {
                    Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                    User = "steve"
                };
            });

            var ts = Math.Floor(Hawk.ConvertToUnixTimestamp(DateTime.Now) / 1000).ToString();

            var headers = new NameValueCollection();

            var request = new Mock<IHttpRequest>();
            request.SetupGet(r => r.AbsoluteUri).Returns("http://example.com:8080/resource/4?filter=a");
            request.SetupGet(r => r.HttpMethod).Returns("GET");
            request.SetupGet(r => r.Headers).Returns(headers);

            headers.Add("Host", "localhost");
            headers.Add("Authorization", "Hawk id = \"456\", ts = \"" + ts + "\", nonce=\"k3j4h2\", mac = \"qrP6b5tiS2CO330rpjUEym/USBM=\", ext = \"hello\"");

            var response = new Mock<IHttpResponse>();

            filter.Execute(request.Object, response.Object, new object());

            response.VerifySet(r => r.StatusCode = (int)HttpStatusCode.Unauthorized);
            response.VerifySet(r => r.StatusDescription = "Invalid credentials");
        }

        [TestMethod]
        public void ShouldFailOnUnknownCredentialsAlgorithm()
        {
            var filter = new HawkRequestFilter((id) =>
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

            var headers = new NameValueCollection();

            var request = new Mock<IHttpRequest>();
            request.SetupGet(r => r.AbsoluteUri).Returns("http://example.com:8080/resource/4?filter=a");
            request.SetupGet(r => r.HttpMethod).Returns("GET");
            request.SetupGet(r => r.Headers).Returns(headers);

            headers.Add("Host", "localhost");
            headers.Add("Authorization", "Hawk id = \"456\", ts = \"" + ts + "\", nonce=\"k3j4h2\", mac = \"qrP6b5tiS2CO330rpjUEym/USBM=\", ext = \"hello\"");

            var response = new Mock<IHttpResponse>();

            filter.Execute(request.Object, response.Object, new object());

            response.VerifySet(r => r.StatusCode = (int)HttpStatusCode.Unauthorized);
            response.VerifySet(r => r.StatusDescription = "Unknown algorithm");
        }

        [TestMethod]
        public void ShouldFailOnUnknownBadMac()
        {
            var filter = new HawkRequestFilter((id) =>
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

            var headers = new NameValueCollection();

            var request = new Mock<IHttpRequest>();
            request.SetupGet(r => r.AbsoluteUri).Returns("http://example.com:8080/resource/4?filter=a");
            request.SetupGet(r => r.HttpMethod).Returns("GET");
            request.SetupGet(r => r.Headers).Returns(headers);

            headers.Add("Host", "localhost");
            headers.Add("Authorization", "Hawk id = \"456\", ts = \"" + ts + "\", nonce=\"k3j4h2\", mac = \"qrP6b5tiS2CO330rpjUEym/USBM=\", ext = \"hello\"");

            var response = new Mock<IHttpResponse>();

            filter.Execute(request.Object, response.Object, new object());

            response.VerifySet(r => r.StatusCode = (int)HttpStatusCode.Unauthorized);
            response.VerifySet(r => r.StatusDescription = "Bad mac");
        }

        [TestMethod]
        public void ShouldReturnChallengeOnEmptyAuthHeaderWithStatusUnauthorized()
        {
            var filter = new HawkRequestFilter((id) =>
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

            var headers = new NameValueCollection();

            var request = new Mock<IHttpRequest>();
            request.SetupGet(r => r.AbsoluteUri).Returns("http://example.com:8080/resource/4?filter=a");
            request.SetupGet(r => r.HttpMethod).Returns("GET");
            request.SetupGet(r => r.Headers).Returns(headers);

            headers.Add("Host", "localhost");

            var response = new Mock<IHttpResponse>();

            filter.Execute(request.Object, response.Object, new object());

            response.VerifySet(r => r.StatusCode = (int)HttpStatusCode.Unauthorized);
            response.Verify(r => r.AddHeader("WwwAuthenticate", It.Is<string>(s => s.Contains("Hawk"))));
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

            var filter = new HawkRequestFilter((id) =>
            {
                return credential;
            });

            var ts = Math.Floor(Hawk.ConvertToUnixTimestamp(DateTime.Now) / 1000);
            var mac = Hawk.CalculateMac("example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), "hello", ts.ToString(), "j4h3g2", credential, "header");

            var headers = new NameValueCollection();

            var request = new Mock<IHttpRequest>();
            request.SetupGet(r => r.AbsoluteUri).Returns("http://example.com:8080/resource/4?filter=a");
            request.SetupGet(r => r.HttpMethod).Returns("GET");
            request.SetupGet(r => r.Headers).Returns(headers);

            headers.Add("Host", "example.com");
            headers.Add("Authorization", "Hawk " + string.Format("id = \"456\", ts = \"{0}\", nonce=\"j4h3g2\", mac = \"{1}\", ext = \"hello\"",
                ts, mac));

            var response = new Mock<IHttpResponse>();
            response.Setup(r => r.StatusCode).Throws(new Exception("StatusCode should not be set"));

            filter.Execute(request.Object, response.Object, new object());
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

            var filter = new HawkRequestFilter((id) =>
            {
                return credential;
            });

            var ts = Math.Floor(Hawk.ConvertToUnixTimestamp(DateTime.Now) / 1000);
            var mac = Hawk.CalculateMac("example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), "hello", ts.ToString(), "j4h3g2", credential, "header");

            var headers = new NameValueCollection();

            var request = new Mock<IHttpRequest>();
            request.SetupGet(r => r.AbsoluteUri).Returns("http://example.com:8080/resource/4?filter=a");
            request.SetupGet(r => r.HttpMethod).Returns("GET");
            request.SetupGet(r => r.Headers).Returns(headers);

            headers.Add("Host", "example.com");
            headers.Add("Authorization", "Hawk " + string.Format("id = \"456\", ts = \"{0}\", nonce=\"j4h3g2\", mac = \"{1}\", ext = \"hello\"",
                ts, mac));

            var response = new Mock<IHttpResponse>();
            response.Setup(r => r.StatusCode).Throws(new Exception("StatusCode should not be set"));

            filter.Execute(request.Object, response.Object, new object());
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
