using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HawkNet.WebApi
{
    public interface IHawkCredentialRepository
    {
        Task<HawkCredential> GetCredentialsAsync(string id);
    }
}
