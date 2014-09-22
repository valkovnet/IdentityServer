namespace Identity.Membership.Interfaces
{
    public interface IIdentityConfiguration
    {
        IGlobalConfiguration Global { get; }

        IWSFederationConfiguration WSFederation { get; }

        IKeyMaterialConfiguration Keys { get; }

        IWSTrustConfiguration WSTrust { get; }
    }
}
