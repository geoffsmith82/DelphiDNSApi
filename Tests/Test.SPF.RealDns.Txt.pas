unit Test.SPF.RealDns.Txt;

interface

uses
  System.SysUtils,
  DUnitX.TestFramework,
  Test.SPF.RealDns.Base,
  DNS.SPF.Types;

type
  [TestFixture]
  TRealDnsTxtTests = class(TRealDnsTestBase)
  public
    [Test]
    procedure GoogleTxt_ContainsSpf;
  end;

implementation

procedure TRealDnsTxtTests.GoogleTxt_ContainsSpf;
var
  Resolver: ISpfDnsResolver;
  Txts: TArray<string>;
  Status: TDnsStatus;
  Found: Boolean;
begin
  Resolver := CreateResolver;

  Status := Resolver.QueryTXT('google.com', Txts);
  Assert.AreEqual(dnsOk, Status);

  Found := False;
  for var S in Txts do
    if Pos('v=spf1', LowerCase(S)) > 0 then
      Found := True;

  Assert.IsTrue(Found, 'google.com should publish SPF');
end;

initialization
  TDUnitX.RegisterTestFixture(TRealDnsTxtTests);

end.

