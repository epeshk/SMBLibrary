using System.Runtime.CompilerServices;
using System.Text;

namespace SMBLibrary.Tests;

public static class EncodingProviderRegistrar
{
    [ModuleInitializer]
    public static void Register() => Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
}