using System;
using System.Collections.Generic;
using Identity.Membership.Interfaces;
using Identity.Membership.Types;

namespace Identity.Membership.Repositories
{
    public class RelyingPartyRepository : IRelyingPartyRepository
    {
        public bool TryGet(string realm, out RelyingParty relyingParty)
        {            
            relyingParty = new RelyingParty()
                {
                    Realm = new Uri("https://client.identity.com/"),
                    ReplyTo = new Uri("https://client.identity.com/")
                };
            return true;           
        }     
    }
}
