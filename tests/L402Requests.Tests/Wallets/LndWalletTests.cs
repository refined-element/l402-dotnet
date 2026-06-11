using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FluentAssertions;
using L402Requests.Wallets;

namespace L402Requests.Tests.Wallets;

internal class MockLndHandler : HttpMessageHandler
{
    public HttpStatusCode StatusCode { get; set; } = HttpStatusCode.OK;
    public string? ResponseBody { get; set; }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        return Task.FromResult(new HttpResponseMessage(StatusCode)
        {
            Content = new StringContent(ResponseBody ?? "", Encoding.UTF8, "application/json"),
        });
    }
}

public class LndWalletTests
{
    [Fact]
    public async Task PayInvoiceAsync_Succeeded_ReturnsHexPreimage()
    {
        // Base64-encoded preimage that should be converted to hex
        var preimageBytes = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
        var preimageBase64 = Convert.ToBase64String(preimageBytes);

        var handler = new MockLndHandler
        {
            ResponseBody = "{\"result\": {\"status\": \"SUCCEEDED\", \"payment_preimage\": \"" + preimageBase64 + "\"}}",
        };

        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://localhost:8080") };
        var wallet = new LndWallet(httpClient);

        var preimage = await wallet.PayInvoiceAsync("lnbc10u1ptest");

        preimage.Should().Be("deadbeef");
    }

    [Fact]
    public async Task PayInvoiceAsync_AlreadyHex_ReturnsAsIs()
    {
        // Use a hex string that is NOT valid base64 (odd padding), so the fallback path is taken
        var hexPreimage = "0123456789abcdef0";  // Not valid base64 (length not multiple of 4, invalid chars)
        var handler = new MockLndHandler
        {
            ResponseBody = "{\"result\": {\"status\": \"SUCCEEDED\", \"payment_preimage\": \"" + hexPreimage + "\"}}",
        };

        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://localhost:8080") };
        var wallet = new LndWallet(httpClient);

        var preimage = await wallet.PayInvoiceAsync("lnbc10u1ptest");

        preimage.Should().Be(hexPreimage);
    }

    [Fact]
    public async Task PayInvoiceAsync_Failed_Throws()
    {
        var handler = new MockLndHandler
        {
            ResponseBody = """{"result": {"status": "FAILED", "failure_reason": "INSUFFICIENT_BALANCE"}}""",
        };

        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://localhost:8080") };
        var wallet = new LndWallet(httpClient);

        var act = () => wallet.PayInvoiceAsync("lnbc10u1ptest");

        await act.Should().ThrowAsync<PaymentFailedException>()
            .Where(e => e.Reason.Contains("INSUFFICIENT_BALANCE"));
    }

    [Fact]
    public async Task PayInvoiceAsync_HttpError_Throws()
    {
        var handler = new MockLndHandler { StatusCode = HttpStatusCode.InternalServerError, ResponseBody = "error" };

        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://localhost:8080") };
        var wallet = new LndWallet(httpClient);

        var act = () => wallet.PayInvoiceAsync("lnbc10u1ptest");

        await act.Should().ThrowAsync<PaymentFailedException>();
    }

    [Fact]
    public async Task PayInvoiceAsync_NoResponse_Throws()
    {
        var handler = new MockLndHandler { ResponseBody = "" };

        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://localhost:8080") };
        var wallet = new LndWallet(httpClient);

        var act = () => wallet.PayInvoiceAsync("lnbc10u1ptest");

        await act.Should().ThrowAsync<PaymentFailedException>()
            .Where(e => e.Reason.Contains("No response from LND"));
    }

    [Fact]
    public async Task PayInvoiceAsync_StreamingJson_ParsesLastLine()
    {
        var preimageBytes = new byte[] { 0xAB, 0xCD };
        var preimageBase64 = Convert.ToBase64String(preimageBytes);

        var handler = new MockLndHandler
        {
            ResponseBody = "{\"result\": {\"status\": \"IN_FLIGHT\"}}\n{\"result\": {\"status\": \"SUCCEEDED\", \"payment_preimage\": \"" + preimageBase64 + "\"}}",
        };

        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://localhost:8080") };
        var wallet = new LndWallet(httpClient);

        var preimage = await wallet.PayInvoiceAsync("lnbc10u1ptest");

        preimage.Should().Be("abcd");
    }

    [Fact]
    public void Properties_Correct()
    {
        using var wallet = new LndWallet("https://localhost:8080", "deadbeef");
        wallet.Name.Should().Be("LND");
        wallet.SupportsPreimage.Should().BeTrue();
    }

    // --- TLS validation (security: MITM prevention on the LND REST connection) ---

    // Generates a throwaway self-signed cert for TLS-validation unit tests.
    // Neutral name (no "secret-..." literal) so gitleaks doesn't flag it.
    private static X509Certificate2 MakeTestCert(string cn)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(
            $"CN={cn}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddYears(1));
    }

    [Fact]
    public void Default_DoesNotBlindlyAcceptAllCerts()
    {
        // The old code returned `=> true` unconditionally. The default (no cert path,
        // no insecure opt-in) must NOT accept a cert that the platform rejected.
        using var serverCert = MakeTestCert("untrusted-lnd-server");

        var accepted = LndWallet.ValidateServerCertificate(
            pinnedCert: null,
            insecure: false,
            serverCert: serverCert,
            chain: null,
            sslErrors: SslPolicyErrors.RemoteCertificateChainErrors);

        accepted.Should().BeFalse(
            "default validation must defer to the platform and reject untrusted chains, not blindly accept");
    }

    [Fact]
    public void PinnedCert_RejectsMismatchedServerCert()
    {
        // With a pinned tlsCert supplied, a DIFFERENT server cert presented during
        // the handshake must be REJECTED (this is the MITM case the old code allowed).
        using var pinnedCert = MakeTestCert("real-lnd-node");
        using var attackerCert = MakeTestCert("mitm-attacker");

        var accepted = LndWallet.ValidateServerCertificate(
            pinnedCert: pinnedCert,
            insecure: false,
            serverCert: attackerCert,
            chain: null,
            sslErrors: SslPolicyErrors.RemoteCertificateChainErrors);

        accepted.Should().BeFalse("a server cert that doesn't match the pinned cert must be rejected");
    }

    [Fact]
    public void PinnedCert_AcceptsMatchingServerCert()
    {
        // The pinned self-signed cert presented by the server is the legitimate case —
        // platform validation would fail (self-signed) but the pin makes it trusted.
        using var pinnedCert = MakeTestCert("real-lnd-node");
        using var presented = new X509Certificate2(pinnedCert.RawData);

        var accepted = LndWallet.ValidateServerCertificate(
            pinnedCert: pinnedCert,
            insecure: false,
            serverCert: presented,
            chain: null,
            sslErrors: SslPolicyErrors.RemoteCertificateChainErrors);

        accepted.Should().BeTrue("the exact pinned cert presented by the server must be trusted");
    }

    [Fact]
    public void Insecure_OptIn_AcceptsAnyCert()
    {
        // Insecure must be an explicit opt-in (not the default). When set, it accepts
        // any cert — preserving the old behavior for users who knowingly opt in.
        using var anyCert = MakeTestCert("anything");

        var accepted = LndWallet.ValidateServerCertificate(
            pinnedCert: null,
            insecure: true,
            serverCert: anyCert,
            chain: null,
            sslErrors: SslPolicyErrors.RemoteCertificateChainErrors);

        accepted.Should().BeTrue("explicit insecure opt-in accepts any cert");
    }

    [Fact]
    public void Default_AcceptsWhenNoSslErrors()
    {
        // A normally-trusted server (no SSL policy errors) must pass through the
        // default path. This ensures we didn't break the happy path for valid CAs.
        using var serverCert = MakeTestCert("trusted-by-platform");

        var accepted = LndWallet.ValidateServerCertificate(
            pinnedCert: null,
            insecure: false,
            serverCert: serverCert,
            chain: null,
            sslErrors: SslPolicyErrors.None);

        accepted.Should().BeTrue("when the platform reports no SSL errors, the cert is valid");
    }
}
