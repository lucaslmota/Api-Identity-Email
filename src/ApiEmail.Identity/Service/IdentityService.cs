using ApiEmail.Identity.Configurations;
using ApiMail.Aplication.DTOs.Request;
using ApiMail.Aplication.DTOs.Response;
using ApiMail.Aplication.Entity;
using ApiMail.Aplication.Interface.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ApiEmail.Identity.Service
{
    public class IdentityService : IIdentityService
    {
        private readonly SignInManager<ApplicationUser> _singInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IEmailService _emailService;
        private readonly JwtOptions _jwtOptions;
        private readonly IConfiguration _configuration;

        public IdentityService(SignInManager<ApplicationUser> singInManager, 
                               UserManager<ApplicationUser> userManager, 
                               IOptions<JwtOptions> jwtOptions, 
                               IEmailService emailService,
                               IConfiguration configuration)
        {
            _singInManager = singInManager;
            _userManager = userManager;
            _jwtOptions = jwtOptions.Value;
            _emailService = emailService;
            _configuration = configuration;
        }

        public async Task<UsuarioCadastroResponse> CadastrarUsuario(UsuarioCadastroRequest usuarioCadastro)
        {
            var identityUser = new ApplicationUser
            {
                UserName = usuarioCadastro.Email,
                Email = usuarioCadastro.Email
            };

            var result = await _userManager.CreateAsync(identityUser, usuarioCadastro.Senha);

            if (result.Succeeded)
            {
                //Efeito funcional: com LockoutEnabled = false
                //o sistema de Identity não aplicará bloqueio por tentativas falhas
                //(ou seja, MaxFailedAccessAttempts passa a ser ignorado para esse usuário).
                await _userManager.SetLockoutEnabledAsync(identityUser, false);
            }

            var usuarioCadastroResponse = new UsuarioCadastroResponse(result.Succeeded);
            if (!result.Succeeded && result.Errors.Count() > 0)
            {
                usuarioCadastroResponse.AdicionarErros(result.Errors.Select(r => r.Description));
            }

            var token = await GenerateEmailConfirmationTokenAsync(identityUser);

            var baseUrl = _configuration["AppSetting:BaseUrl"] ?? throw new InvalidOperationException("Url base não configurada");

            var confirmationLink = $"{baseUrl}/api/v1/usuario/confirmemail?userId={identityUser.Id}&token={token}";

            await _emailService.SendRegistrationConfirmationEmailAsync(identityUser.Email, "Lucas Teste", confirmationLink);
            return usuarioCadastroResponse;
        }

        public async Task<UsuarioLoginResponse> Login(UsuarioLoginRequest usuarioLogin)
        {
            var result = await _singInManager.PasswordSignInAsync(usuarioLogin.Email, usuarioLogin.Senha, false, true);

            if (result.Succeeded)
                return await GerarCredenciais(usuarioLogin.Email);

            var usuarioLoginResponse = new UsuarioLoginResponse();
            if (!result.Succeeded)
            {
                if (result.IsLockedOut)
                    usuarioLoginResponse.AdicionarErro("Essa conta está bloqueada");
                else if (result.IsNotAllowed)
                    usuarioLoginResponse.AdicionarErro("Essa conta não tem permissão para fazer login");
                else if (result.RequiresTwoFactor)
                    usuarioLoginResponse.AdicionarErro("É necessário confirmar o login no seu segundo fator de autenticação");
                else
                    usuarioLoginResponse.AdicionarErro("Usuário ou senha estão incorretos");
            }
            return usuarioLoginResponse;
        }

        private async Task<UsuarioLoginResponse> GerarCredenciais(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            var accessTokenClaims = await ObterClaims(user, adicionarClaimsUsuario: true);
            var refreshTokenClaims = await ObterClaims(user, adicionarClaimsUsuario: true);

            var dataExpiracaoAccessToken = DateTime.Now.AddSeconds(_jwtOptions.AccessTokenExpiration);
            var dataExpiracaoRefreshToken = DateTime.Now.AddSeconds(_jwtOptions.RefreshTokenExpiration);

            var accessToken = GerarToken(accessTokenClaims, dataExpiracaoAccessToken);
            var refreshToken = GerarToken(refreshTokenClaims, dataExpiracaoRefreshToken);

            return new UsuarioLoginResponse
            (
                sucesso: true,
                accessToken: accessToken,
                refreshToken: refreshToken
            );
        }

        private string GerarToken(IEnumerable<Claim> claims, DateTime dataExpiracao)
        {
            var agora = DateTime.UtcNow;
            if(dataExpiracao < agora)
            {
                dataExpiracao = agora.AddMinutes(30);
            }
            var jwt = new JwtSecurityToken(
                issuer: _jwtOptions.Issuer,
                audience: _jwtOptions.Audience,
                claims: claims,
                notBefore: agora,
                expires: dataExpiracao,
                signingCredentials: _jwtOptions.SigningCredentials);

            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }

        private async Task<IList<Claim>> ObterClaims(ApplicationUser user, bool adicionarClaimsUsuario)
        {
            var claims = new List<Claim>();

            claims.Add(new Claim(JwtRegisteredClaimNames.Sub, user.Id));
            claims.Add(new Claim(JwtRegisteredClaimNames.Email, user.Email));
            claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
            claims.Add(new Claim(JwtRegisteredClaimNames.Nbf, DateTime.Now.ToString()));
            claims.Add(new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.Now.ToUnixTimeSeconds().ToString()));

            if (adicionarClaimsUsuario)
            {
                var userClaims = await _userManager.GetClaimsAsync(user);
                var roles = await _userManager.GetRolesAsync(user);

                claims.AddRange(userClaims);

                foreach (var role in roles)
                    claims.Add(new Claim("role", role));
            }

            return claims;
        }

        public async Task<string> GenerateEmailConfirmationTokenAsync(ApplicationUser applicationUser)
        {
            ArgumentNullException.ThrowIfNull(applicationUser);
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(applicationUser);
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
            return encodedToken;
        }

        public async Task<IdentityResult> ConfirmEmail(Guid id, string token)
        {
            if(id == null || string.IsNullOrEmpty(token))
            {
                return IdentityResult.Failed(new IdentityError { Description = "Id ou Token inválidos!"});
            }

            var user = await _userManager.FindByIdAsync(id.ToString());
            if(user is null)
            {
                return IdentityResult.Failed(new IdentityError { Description = "Usuário não encontrado!" });
            }

            var decodedBytes = WebEncoders.Base64UrlDecode(token);

            var decodedToken = Encoding.UTF8.GetString(decodedBytes);

            var result = await _userManager.ConfirmEmailAsync(user, decodedToken);

            if (result.Succeeded)
            {
                var baseUrl = _configuration["AppSetting:BaseUrl"] ?? throw new InvalidOperationException("BaseUrl não configurada!");
                var loginLink = $"{baseUrl}/api/v1/usuario/confirmemail";
                await _emailService.SendAccountCreatedEmailAsync(user.Email!, "Lucas mota", loginLink);
            }
            return result;
        }
    }
}