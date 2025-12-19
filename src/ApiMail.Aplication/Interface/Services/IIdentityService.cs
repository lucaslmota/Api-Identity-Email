using ApiMail.Aplication.DTOs.Request;
using ApiMail.Aplication.DTOs.Response;
using ApiMail.Aplication.Entity;
using Microsoft.AspNetCore.Identity;

namespace ApiMail.Aplication.Interface.Services
{
    public interface IIdentityService
    {
        Task<UsuarioCadastroResponse> CadastrarUsuario(UsuarioCadastroRequest usuarioCadastro);
        Task<string> GenerateEmailConfirmationTokenAsync(ApplicationUser applicationUser);
        Task<IdentityResult> ConfirmEmail(Guid id, string token);
        Task<UsuarioLoginResponse> Login(UsuarioLoginRequest usuarioLogin);

    }
}