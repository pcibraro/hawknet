using System;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.IdentityModel.Claims;
using System.Net;

namespace HawkNet.WCF
{
    class HawkAuthorizationManager : ServiceAuthorizationManager
    {
        public bool SendChallenge { get; set; }

        public HawkAuthorizationManager(bool sendChallenge) : base()
        {
            SendChallenge = sendChallenge;
        }

        protected override bool CheckAccessCore(OperationContext operationContext)
        {
            if (!operationContext.ServiceSecurityContext.AuthorizationContext.ClaimSets.Any())
            {
                if (SendChallenge)
                {
                    var newReply = Message.CreateMessage(MessageVersion.None, null);
                    var responseProperty = new HttpResponseMessageProperty() { StatusCode = HttpStatusCode.Unauthorized };

                    var ts = Hawk.ConvertToUnixTimestamp(DateTime.Now).ToString();
                    var challenge = string.Format("ts=\"{0}\" ntp=\"{1}\"",
                        ts, "pool.ntp.org");

                    responseProperty.Headers.Add("WWW-Authenticate", challenge);

                    newReply.Properties[HttpResponseMessageProperty.Name] = responseProperty;

                    //overwrite the original reply with the unauthorized message.
                    operationContext.RequestContext.Reply(newReply);
                }
                return false;
            }

            return base.CheckAccessCore(operationContext);
        }
    }
}
