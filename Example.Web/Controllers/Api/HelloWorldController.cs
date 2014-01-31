using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;

namespace Example.Web.Controllers.Api
{
    public class HelloWorldController : ApiController
    {
        public string Get()
        {
            return "hello " + this.User.Identity.Name;
        }
    }
}