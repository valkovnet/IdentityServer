namespace Identity.Membership.Tokens
{
    public class RepositoryUserNameSecurityTokenHandler : GenericUserNameSecurityTokenHandler
    {        
        protected override bool ValidateUserNameCredentialCore(string userName, string password)
        {            
            return true;
        }
    }
}
