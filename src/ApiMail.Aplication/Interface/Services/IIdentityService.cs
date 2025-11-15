using ApiMail.Aplication.DTOs.Request;
using ApiMail.Aplication.DTOs.Response;

namespace ApiMail.Aplication.Interface.Services
{
    public interface IIdentityService
    {
        Task<UsuarioCadastroResponse> CadastrarUsuario(UsuarioCadastroRequest usuarioCadastro);
        Task<UsuarioLoginResponse> Login(UsuarioLoginRequest usuarioLogin);
    }
}