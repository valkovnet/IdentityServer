using System.Collections.Generic;
using Identity.Membership.Types;

namespace Identity.Membership.Interfaces
{
    public interface IRelyingPartyRepository
    {
        bool TryGet(string realm, out RelyingParty relyingParty);       
    }
}
