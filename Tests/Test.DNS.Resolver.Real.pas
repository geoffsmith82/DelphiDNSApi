unit Test.DNS.Resolver.Real;

interface

uses
  DUnitX.TestFramework,
  DNS.SPF.DnsWin32,
  DNS.SPF.Types;

type
  [TestFixture]
  TRealDnsResolverTests = class
  private
    Resolver: ISpfDnsResolver;
  public
    [Setup] procedure Setup;

    [Test] procedure TXT_Resolves;
    [Test] procedure A_Resolves;
    [Test] procedure AAAA_Resolves;
    [Test] procedure MX_Resolves;
  end;

implementation

procedure TRealDnsResolverTests.Setup;
begin
  Resolver := TSpfWinDnsResolver.Create;
end;

procedure TRealDnsResolverTests.TXT_Resolves;
var
  Txts: TArray<string>;
begin
  Assert.AreEqual(
    dnsOk,
    Resolver.QueryTXT('google.com', Txts)
  );

  Assert.IsTrue(
    Length(Txts) > 0,
    'TXT records should be returned'
  );
end;


procedure TRealDnsResolverTests.A_Resolves;
var
  Addrs: TArray<string>;
begin
  Assert.AreEqual(
    dnsOk,
    Resolver.QueryA('google.com', Addrs)
  );

  Assert.IsTrue(
    Length(Addrs) > 0,
    'IPv4 addresses expected'
  );
end;


procedure TRealDnsResolverTests.AAAA_Resolves;
var
  Addrs: TArray<string>;
  Status: TDnsStatus;
begin
  Status := Resolver.QueryAAAA('google.com', Addrs);

  Assert.IsTrue(
    Status in [dnsOk, dnsNoData],
    'AAAA may or may not exist'
  );

  if Status = dnsOk then
    Assert.IsTrue(Length(Addrs) > 0);
end;


procedure TRealDnsResolverTests.MX_Resolves;
var
  MXs: TArray<String>;
begin
  Assert.AreEqual(
    dnsOk,
    Resolver.QueryMX('google.com', MXs)
  );

  Assert.IsTrue(
    Length(MXs) > 0,
    'MX records expected'
  );
end;


end.
