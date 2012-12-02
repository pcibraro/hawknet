using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.SelfHost;
using HawkNet;

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
                    return new HawkMessageHandler.HawkCredential
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

                var credential = new HawkClientMessageHandler.HawkCredential
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
                Console.WriteLine("Http Status Code {0}", response.StatusCode);

                Console.ReadLine();
            }

        }
        
    }

    public class HelloWorldController : ApiController
    {
        public string Get()
        {
            return "hello";
        }
    }
}
