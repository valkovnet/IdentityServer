using Identity.Membership.Interfaces;

namespace Identity.Membership.Configurations
{
    public class IdentityIdentityConfiguration : IIdentityConfiguration
    {
        public IGlobalConfiguration Global
        {
            get
            {
                return new GlobalConfiguration();
            }
        }
        
        public IWSFederationConfiguration WSFederation
        {
            get
            {
                return new WSFederationConfiguration();
            }
        }

        public IKeyMaterialConfiguration Keys
        {
            get
            {
                return new KeyMaterialConfiguration();
            }
        }

        public IWSTrustConfiguration WSTrust
        {
            get
            {
                return new WSTrustConfiguration();
            }
        }
    }
}
