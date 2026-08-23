using System.Net;
using System.Text;
using FluentAssertions;

namespace L402Requests.Tests;

/// <summary>
/// Payment-Receipt response header parsing (draft-00). Tolerant by design:
/// the header is optional, and a malformed receipt must never fail an
/// otherwise-successful payment.
/// </summary>
public class PaymentReceiptTests
{
    private const string TestPaymentHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    private const string ReceiptJson =
        "{\"challengeId\":\"chg_fixture01\",\"method\":\"lightning\",\"reference\":\"" + TestPaymentHash + "\",\"status\":\"settled\",\"timestamp\":\"2026-08-23T00:00:00Z\"}";

    private static string B64UrlNoPad(string s) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(s))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string B64UrlPadded(string s) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(s))
            .Replace('+', '-').Replace('/', '_');

    private static HttpResponseMessage ResponseWithReceipt(string? headerValue)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK);
        if (headerValue is not null)
            response.Headers.TryAddWithoutValidation("Payment-Receipt", headerValue);
        return response;
    }

    [Fact]
    public void TryParse_ValidReceipt_ReturnsFields()
    {
        var receipt = PaymentReceipt.TryParse(ResponseWithReceipt(B64UrlNoPad(ReceiptJson)));

        receipt.Should().NotBeNull();
        receipt!.ChallengeId.Should().Be("chg_fixture01");
        receipt.Method.Should().Be("lightning");
        receipt.Reference.Should().Be(TestPaymentHash);
        receipt.Status.Should().Be("settled");
        receipt.Timestamp.Should().Be("2026-08-23T00:00:00Z");
    }

    [Fact]
    public void TryParse_PaddedBase64_Accepted()
    {
        var padded = B64UrlPadded(ReceiptJson);
        var receipt = PaymentReceipt.TryParse(ResponseWithReceipt(padded));

        receipt.Should().NotBeNull();
        receipt!.Reference.Should().Be(TestPaymentHash);
    }

    [Fact]
    public void TryParse_NoHeader_ReturnsNull()
    {
        PaymentReceipt.TryParse(ResponseWithReceipt(null)).Should().BeNull();
    }

    [Fact]
    public void TryParse_BadBase64_ReturnsNull()
    {
        PaymentReceipt.TryParse(ResponseWithReceipt("!!!not-base64!!!")).Should().BeNull();
    }

    [Fact]
    public void TryParse_BadJson_ReturnsNull()
    {
        PaymentReceipt.TryParse(ResponseWithReceipt(B64UrlNoPad("not json"))).Should().BeNull();
    }

    [Fact]
    public void TryParse_MissingFields_ToleratedAsNulls()
    {
        var receipt = PaymentReceipt.TryParse(
            ResponseWithReceipt(B64UrlNoPad("{\"reference\":\"" + TestPaymentHash + "\"}")));

        receipt.Should().NotBeNull();
        receipt!.Reference.Should().Be(TestPaymentHash);
        receipt.ChallengeId.Should().BeNull();
        receipt.Status.Should().BeNull();
    }
}
