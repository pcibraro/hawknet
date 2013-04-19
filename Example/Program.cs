using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.SelfHost;
using HawkNet;
using HawkNet.WebApi;
using System.Web.Http.Dispatcher;

namespace Example
{
    class Program
    {
        static void Main(string[] args)
        {
            var config = new HttpSelfHostConfiguration("http://localhost:8091");
            //config.Filters.Add(new RequiresHawkAttribute(typeof(HawkRepository)));

            var handler = new HawkMessageHandler(new HttpControllerDispatcher(config),
                (id) =>
                {
                    return new HawkCredential
                    {
                        Id = id,
                        Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                        Algorithm = "hmacsha256",
                        User = "steve"
                    };
                });

            config.Routes.MapHttpRoute(
                "Filter", "api/filter",
                new
                {
                    controller = "HelloWorldWithFilter"
                });

            config.Routes.MapHttpRoute(
                "API Default", "api/{controller}/{id}",
                new
                {
                    id = RouteParameter.Optional,
                    controller = "HelloWorld"
                },
                null,
                handler
                );

            using (HttpSelfHostServer server = new HttpSelfHostServer(config))
            {
                server.OpenAsync().Wait();
                Console.WriteLine("Press Enter to quit.");

                var credential = new HawkCredential
                {
                    Id = "dh37fgj492je",
                    Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                    Algorithm = "hmacsha256",
                    User = "steve"
                };

                var clientHandler = new HawkClientMessageHandler(new HttpClientHandler(), credential, "some-app-data");
                var client = new HttpClient(clientHandler);

                var request = new HttpRequestMessage(HttpMethod.Get, "http://localhost:8091/Api/HelloWorld");
                request.Headers.Host = "localhost";

                var response = client.SendAsync(request).Result;
                string message = response.Content.ReadAsStringAsync().Result;
                Console.WriteLine("Response {0} - Http Status Code {1}", message, response.StatusCode);

                var client2 = new HttpClient();
                
                request = new HttpRequestMessage(HttpMethod.Get, "http://localhost:8091/Api/HelloWorldAnonymous");
                request.Headers.Host = "localhost";

                response = client2.SendAsync(request).Result;
                message = response.Content.ReadAsStringAsync().Result;
                Console.WriteLine("Response {0} - Http Status Code {1}", message, response.StatusCode);

                var client3 = new HttpClient();

                var bewit = Hawk.GetBewit("localhost", new Uri("http://localhost:8091/Api/HelloWorld"), credential, 60000);

                request = new HttpRequestMessage(HttpMethod.Get, "http://localhost:8091/Api/HelloWorld?bewit=" + bewit);
                request.Headers.Host = "localhost";

                response = client3.SendAsync(request).Result;
                
                message = response.Content.ReadAsStringAsync().Result;
                Console.WriteLine("Response {0} - Http Status Code {1}", message, response.StatusCode);

                var client4 = new HttpClient(clientHandler);

                var request4 = new HttpRequestMessage(HttpMethod.Get, "http://localhost:8091/api/filter");
                request4.Headers.Host = "localhost";

                var response4 = client4.SendAsync(request4).Result;
                string message4 = response4.Content.ReadAsStringAsync().Result;
                Console.WriteLine("Response {0} - Http Status Code {1}", message4, response4.StatusCode);

                Console.WriteLine("Press a key to close the app");
                Console.ReadLine();
            }
        }
    }

    public class HawkRepository : IHawkCredentialRepository
    {
        public HawkCredential Get(string identifier)
        {
            var credential = new HawkCredential
            {
                Id = "dh37fgj492je",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                Algorithm = "hmacsha256",
                User = "steve"
            };

            return credential;
        }
    }

    public class HelloWorldController : ApiController
    {
        [Authorize]
        public string Get()
        {
            return "hello " + User.Identity.Name;
        }
    }

    public class HelloWorldAnonymousController : ApiController
    {
        [AllowAnonymous]
        public string Get()
        {
            return "hello anonymous";
        }
    }

    
    public class HelloWorldWithFilterController : ApiController
    {
        [RequiresHawkAttribute(typeof(HawkRepository))]
        public string Get()
        {
            return "hello " + User.Identity.Name;
        }
    }
}
