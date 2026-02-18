using FluentAssertions;

namespace L402Requests.Tests;

public class BudgetControllerTests
{
    [Fact]
    public void Check_WithinLimits_DoesNotThrow()
    {
        var budget = new BudgetController();
        var act = () => budget.Check(500, "example.com");
        act.Should().NotThrow();
    }

    [Fact]
    public void Check_ExceedsPerRequest_Throws()
    {
        var budget = new BudgetController(maxSatsPerRequest: 100);
        var act = () => budget.Check(200, "example.com");
        act.Should().Throw<BudgetExceededException>()
            .Where(e => e.LimitType == "per_request" && e.LimitSats == 100 && e.InvoiceSats == 200);
    }

    [Fact]
    public void Check_ExceedsHourlyLimit_Throws()
    {
        var budget = new BudgetController(maxSatsPerHour: 500, maxSatsPerRequest: 1000);

        budget.Check(300, "example.com");
        budget.RecordPayment(300);

        var act = () => budget.Check(300, "example.com");
        act.Should().Throw<BudgetExceededException>()
            .Where(e => e.LimitType == "per_hour");
    }

    [Fact]
    public void Check_ExceedsDailyLimit_Throws()
    {
        var budget = new BudgetController(maxSatsPerDay: 500, maxSatsPerHour: 10000, maxSatsPerRequest: 1000);

        budget.Check(300, "example.com");
        budget.RecordPayment(300);

        var act = () => budget.Check(300, "example.com");
        act.Should().Throw<BudgetExceededException>()
            .Where(e => e.LimitType == "per_day");
    }

    [Fact]
    public void Check_DomainNotAllowed_Throws()
    {
        var budget = new BudgetController(allowedDomains: new HashSet<string> { "allowed.com" });

        var act = () => budget.Check(100, "evil.com");
        act.Should().Throw<DomainNotAllowedException>()
            .Where(e => e.Domain == "evil.com");
    }

    [Fact]
    public void Check_AllowedDomain_DoesNotThrow()
    {
        var budget = new BudgetController(allowedDomains: new HashSet<string> { "allowed.com" });

        var act = () => budget.Check(100, "allowed.com");
        act.Should().NotThrow();
    }

    [Fact]
    public void Check_DomainAllowlist_CaseInsensitive()
    {
        var budget = new BudgetController(allowedDomains: new HashSet<string> { "Allowed.COM" });

        var act = () => budget.Check(100, "allowed.com");
        act.Should().NotThrow();
    }

    [Fact]
    public void Check_NoDomainAllowlist_AllDomainsAllowed()
    {
        var budget = new BudgetController();

        var act = () => budget.Check(100, "any-domain.com");
        act.Should().NotThrow();
    }

    [Fact]
    public void SpentLastHour_TracksCorrectly()
    {
        var budget = new BudgetController();
        budget.RecordPayment(100);
        budget.RecordPayment(200);

        budget.SpentLastHour().Should().Be(300);
    }

    [Fact]
    public void SpentLastDay_TracksCorrectly()
    {
        var budget = new BudgetController();
        budget.RecordPayment(100);
        budget.RecordPayment(200);

        budget.SpentLastDay().Should().Be(300);
    }

    [Fact]
    public void RecordPayment_AllowsSubsequentChecks()
    {
        var budget = new BudgetController(maxSatsPerHour: 500, maxSatsPerRequest: 1000);

        budget.Check(200);
        budget.RecordPayment(200);

        // Still under limit
        var act = () => budget.Check(200);
        act.Should().NotThrow();

        budget.RecordPayment(200);

        // Now over hourly limit
        act = () => budget.Check(200);
        act.Should().Throw<BudgetExceededException>();
    }

    [Fact]
    public void ConstructFromOptions_Works()
    {
        var options = new L402Options
        {
            MaxSatsPerRequest = 100,
            MaxSatsPerHour = 500,
            MaxSatsPerDay = 1000,
            AllowedDomains = new HashSet<string> { "test.com" },
        };

        var budget = new BudgetController(options);

        var act = () => budget.Check(200, "test.com");
        act.Should().Throw<BudgetExceededException>();
    }
}
