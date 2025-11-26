using Api.Identity.Email.Controllers.Shared;
using ApiMail.Aplication.DTOs.Request;
using ApiMail.Aplication.DTOs.Response;
using ApiMail.Aplication.Interface.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Net;

namespace Api.Identity.Email.Controllers.v1
{
    [ApiVersion("1.0")]
    public class UsuarioController : ApiControllerBase
    {
        private IIdentityService _identityService;
        public UsuarioController(IIdentityService identityService) =>
        _identityService = identityService;

        /// <summary>
        /// Cadastro de usuário.
        /// </summary>
        /// <remarks>
        /// </remarks>
        /// <param name="usuarioCadastro">Dados de cadastro do usuário</param>
        /// <returns></returns>
        /// <response code="200">Usuário criado com sucesso</response>
        /// <response code="400">Retorna erros de validação</response>
        /// <response code="500">Retorna erros caso ocorram</response>
        [ProducesResponseType(typeof(UsuarioCadastroResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        [HttpPost("usuario/cadastro")]

        public async Task<IActionResult> Cadastrar(UsuarioCadastroRequest usuarioCadastro)
        {
            if (!ModelState.IsValid)
                return BadRequest();

            var resultado = await _identityService.CadastrarUsuario(usuarioCadastro);
            if (resultado.Sucesso)
                return Ok(resultado);
            else if (resultado.Erros.Count > 0)
            {
                var problemDetails = new CustomProblemDetails(HttpStatusCode.BadRequest, Request, errors: resultado.Erros);
                return BadRequest(problemDetails);
            }

            return StatusCode(StatusCodes.Status500InternalServerError);
        }

        /// <summary>
        /// Login do usuário via usuário/senha.
        /// </summary>
        /// <remarks>
        /// </remarks>
        /// <param name="usuarioLogin">Dados de login do usuário</param>
        /// <returns></returns>
        /// <response code="200">Login realizado com sucesso</response>
        /// <response code="400">Retorna erros de validação</response>
        /// <response code="401">Erro caso usuário não esteja autorizado</response>
        /// <response code="500">Retorna erros caso ocorram</response>
        [ProducesResponseType(typeof(UsuarioCadastroResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        [HttpPost("usuario/login")]
        public async Task<ActionResult<UsuarioCadastroResponse>> Login(UsuarioLoginRequest usuarioLogin)
        {
            if (!ModelState.IsValid)
                return BadRequest();

            var resultado = await _identityService.Login(usuarioLogin);
            if (resultado.Sucesso)
                return Ok(resultado);

            return Unauthorized();
        }

    }
}
