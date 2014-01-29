using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin.Extensions;
using Microsoft.Owin;
using Microsoft.Owin.Builder;
using Owin;

namespace HawkNet.Owin.Tests
{
    using AppFunc = Func<IDictionary<string, object>, Task>;

    public sealed class AppFuncTransition : OwinMiddleware
    {
        private readonly AppFunc _next;

        public AppFuncTransition(AppFunc next)
            : base(null)
        {
            _next = next;
        }

        public override Task Invoke(IOwinContext context)
        {
            return _next(context.Request.Environment);
        }

        public static void AddConversions(IAppBuilder app)
        {
            app.AddSignatureConversion<AppFunc, OwinMiddleware>(Conversion1);
            app.AddSignatureConversion<OwinMiddleware, AppFunc>(Conversion2);
        }

        private static OwinMiddleware Conversion1(AppFunc next)
        {
            return new AppFuncTransition(next);
        }

        private static AppFunc Conversion2(OwinMiddleware next)
        {
            throw new NotImplementedException();
        }
    }
}
