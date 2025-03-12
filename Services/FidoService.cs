using WebAuthnDemo.Models;
using WebAuthnDemo.Data;
using Microsoft.EntityFrameworkCore;

namespace WebAuthnDemo.Services;

public class FidoService
{
    private readonly ApplicationDbContext _context;

    public FidoService(ApplicationDbContext context)
    {
        _context = context;
    }


}


