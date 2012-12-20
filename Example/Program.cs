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

namespace Example
{
    class Program
    {
        static void Main(string[] args)
        {
            var config = new HttpSelfHostConfiguration("http://localhost:8091");

            config.Routes.MapHttpRoute(
                "API Default", "api/{controller}/{id}",
                new
                {
                    id = RouteParameter.Optional,
                    controller = "HelloWorld"
                });

            var handler = new HawkMessageHandler((id) =>
                {
                    return new HawkCredential
                    {
                        Id = id,
                        Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                        Algorithm = "hmacsha256",
                        User = "steve"
                    };
                });

            config.MessageHandlers.Add(handler);

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

                request = new HttpRequestMessage(HttpMethod.Get, "http://localhost:8091/Api/HelloWorldAnonymous");
                request.Headers.Host = "localhost";

                response = client.SendAsync(request).Result;
                message = response.Content.ReadAsStringAsync().Result;
                Console.WriteLine("Response {0} - Http Status Code {1}", message, response.StatusCode);

                Console.ReadLine();
            }

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
}
