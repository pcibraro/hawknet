using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;
using HawkNet;
using HawkNet.WebApi;
using System.Web.Http.Dispatcher;
using Microsoft.Owin.Hosting;

namespace Example
{
    class Program
    {
        static void Main(string[] args)
        {
            string baseAddress = "http://localhost:8091/";

            //TODO: It looks like there is a bug in the OWIN implementation. The Request URL does not receive
            // the port number

            // Start OWIN host 
            using (WebApp.Start<Startup>(url: baseAddress))
            {
                Console.WriteLine("Press Enter to quit.");

                var credential = new HawkCredential
                {
                    Id = "dh37fgj492je",
                    Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                    Algorithm = "sha256",
                    User = "steve"
                };

                var clientHandler = new HawkClientMessageHandler(new HttpClientHandler(), credential, "some-app-data");
                var client = new HttpClient(clientHandler);

                var request = new HttpRequestMessage(HttpMethod.Get, "http://localhost:8091/Api/HelloWorld");
                request.Headers.Host = "localhost:8091";

                var response = client.SendAsync(request).Result;
                string message = response.Content.ReadAsStringAsync().Result;
                Console.WriteLine("Response {0} - Http Status Code {1}", message, response.StatusCode);

                var client2 = new HttpClient();

                request = new HttpRequestMessage(HttpMethod.Get, "http://localhost:8091/Api/HelloWorldAnonymous");
                request.Headers.Host = "localhost:8091";

                response = client2.SendAsync(request).Result;
                message = response.Content.ReadAsStringAsync().Result;
                Console.WriteLine("Response {0} - Http Status Code {1}", message, response.StatusCode);

                var client3 = new HttpClient();

                var bewit = Hawk.GetBewit("localhost", new Uri("http://localhost:8091/Api/HelloWorld"), credential, 60000);

                request = new HttpRequestMessage(HttpMethod.Get, "http://localhost:8091/Api/HelloWorld?bewit=" + bewit);
                request.Headers.Host = "localhost:8091";

                response = client3.SendAsync(request).Result;

                message = response.Content.ReadAsStringAsync().Result;
                Console.WriteLine("Response {0} - Http Status Code {1}", message, response.StatusCode);
                
                Console.WriteLine("Press a key to close the app");
                Console.ReadLine();
            }
        }
    }

    
    public class HelloWorldController : ApiController
    {
       
        [HawkAuthentication(typeof(HawkCredentialRepository), 60, true)]
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

    //public class HelloWorldWithFilterController : ApiController
    //{
    //    [HawkAuthentication(typeof(HawkCredentialRepository))]
    //    [Authorize]
    //    public string Get()
    //    {
    //        return "hello " + User.Identity.Name;
    //    }
    //}


}
