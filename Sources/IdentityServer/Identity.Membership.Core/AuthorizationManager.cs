using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Claims;

namespace Identity.Membership.Core
{
    public static class Actions
    {
        public const string Issue = "Issue";
        public const string Administration = "Administration";
    }

    public class AuthorizationManager : ClaimsAuthorizationManager
    {
        public const string ActionType = "http://application/claims/authorization/action";
        
        public const string ResourceType = "http://application/claims/authorization/resource";

        public const string Issue = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue";

        public const string WSTrust = "WSTrust";

        public override bool CheckAccess(AuthorizationContext context)
        {
            var action = context.Action.First();
            var id = context.Principal.Identities.First();

            // if application authorization request
            if (action.Type.Equals(ActionType))
            {
                return AuthorizeCore(action, context.Resource, context.Principal.Identity as ClaimsIdentity);
            }

            // if ws-trust issue request
            if (action.Value.Equals(Issue))
            {
                return AuthorizeTokenIssuance(new Collection<Claim> { new Claim(ResourceType, WSTrust) }, id);
            }

            return base.CheckAccess(context);
        }

        protected virtual bool AuthorizeCore(Claim action, Collection<Claim> resource, ClaimsIdentity id)
        {
            switch (action.Value)
            {
                case Actions.Issue:
                    return AuthorizeTokenIssuance(resource, id);
                case Actions.Administration:
                    return AuthorizeAdministration(resource, id);
            }

            return false;
        }

        protected virtual bool AuthorizeTokenIssuance(Collection<Claim> resource, ClaimsIdentity id)
        {
            var roleValueClaim = id.HasClaim(ClaimTypes.Role, "IdentityServerUsers");
            return roleValueClaim;

            //TODO
            //if (!this._configurationRepository.Global.EnforceUsersGroupMembership)
            //{
            //    var authResult = id.IsAuthenticated;
            //    if (!authResult)
            //    {
            //        Tracing.Error("Authorization for token issuance failed because the user is anonymous");
            //    }

            //    return authResult;
            //}

            //var authResult = id.IsAuthenticated;
            //if (!authResult)
            //{
            //    throw new ApplicationException("Authorization for token issuance failed because the user is anonymous");
            //}

            //return authResult;

            //var roleResult = id.HasClaim(ClaimTypes.Role, "IdentityServerUsers");
            //if (!roleResult)
            //{
            //    throw new ApplicationException(String.Format("Authorization for token issuance failed because user {0} is not in role", id.Name));
            //}

            //return roleResult;
        }

        protected virtual bool AuthorizeAdministration(Collection<Claim> resource, ClaimsIdentity id)
        {
            var roleResult = id.HasClaim(ClaimTypes.Role, "IdentityServerAdministrators");
            if (!roleResult)
            {
                if (resource[0].Value != "UI")
                {
                    throw new ApplicationException(String.Format("Administration authorization failed because user {0} is not in role", id.Name));
                }
            }

            return roleResult;
        }
    }
}
