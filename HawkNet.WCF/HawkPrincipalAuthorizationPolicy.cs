using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IdentityModel.Claims;
using System.IdentityModel.Policy;
using System.ServiceModel;
using System.Security.Principal;

namespace HawkNet.WCF
{
    class HawkPrincipalAuthorizationPolicy : IAuthorizationPolicy
    {
        string id = Guid.NewGuid().ToString();

        public ClaimSet Issuer
        {
            get { return ClaimSet.System; }
        }

        public string Id
        {
            get { return this.id; }
        }

        public bool Evaluate(EvaluationContext evaluationContext, ref object state)
        {
            object principalValue;

            if (OperationContext.Current.IncomingMessageProperties.TryGetValue("Principal", out principalValue))
            {
                IPrincipal user = principalValue as IPrincipal;
                if (user != null)
                {
                    evaluationContext.AddClaimSet(this, new DefaultClaimSet(this.GetClaims(user)));
                    evaluationContext.Properties["Identities"] = new List<IIdentity>(new IIdentity[] { user.Identity });
                    evaluationContext.Properties["Principal"] = user;

                    return true;
                }
            }
            // This lets people get to the help page, and really anything else that isn't restricted by a PrincipalPermission. Is that what we want?
            /*
            var anonymous = new GenericPrincipal(new GenericIdentity(""), new string[] { });

            evaluationContext.AddClaimSet(this, new DefaultClaimSet(new Claim(ClaimTypes.Anonymous, "", Rights.PossessProperty)));
            evaluationContext.Properties["Identities"] = new List<IIdentity>(new IIdentity[] { anonymous.Identity });
            evaluationContext.Properties["Principal"] = anonymous;

            return true;
            */
            return false;
        }

        public virtual IList<Claim> GetClaims(IPrincipal user)
        {
            IList<Claim> claims = new List<Claim>();
            claims.Add(Claim.CreateNameClaim(user.Identity.Name));
            return claims;
        }

    }
}
