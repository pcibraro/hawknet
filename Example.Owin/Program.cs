using HawkNet;
using Microsoft.Owin.Hosting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Example.Owin
{
    class Program
    {
        static void Main(string[] args)
        {
            using (WebApp.Start<Startup>(new StartOptions { Port = 5000 }))
            {
                Console.WriteLine("Press Enter to quit.");
                
                var credentials = new HawkCredential
                    {
                        Id = "dh37fgj492je",
                        Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                        Algorithm = "sha256",
                        User = "steve"
                    };

                var request = (HttpWebRequest)HttpWebRequest.Create("http://localhost:5000/api/HelloWorld");
                request.SignRequest(credentials);
                request.Method = "GET";
                using (var response = (HttpWebResponse)request.GetResponse())
                {
                    using(var sr = new StreamReader(response.GetResponseStream()))
                    {
                        var content = sr.ReadToEnd();

                        Console.WriteLine("Call made. Status Code " + response.StatusCode + ". Response " + content);
                    }

                   
                }

                Console.ReadKey();
            }
        }
    }
}
