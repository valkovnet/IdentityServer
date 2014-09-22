namespace Identity.Membership.Interfaces
{
    public interface IWSFederationConfiguration
    {
        bool AllowReplyTo { get; set; }

        bool RequireReplyToWithinRealm { get; set; }
    }
}
