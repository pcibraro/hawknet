using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace HawkNet.ServiceStack
{
    /// <summary>
    /// A repository for getting the credentials associated to 
    /// a key identifier
    /// </summary>
    public interface IHawkCredentialRepository
    {
        HawkCredential Get(string identifier);
    }
}
