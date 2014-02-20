using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;

namespace Example.Owin
{
    public class HelloWorldController : ApiController
    {
        //[Authorize]
        public string Get()
        {
            return "hello " + User.Identity.Name;
        }
    }
}
