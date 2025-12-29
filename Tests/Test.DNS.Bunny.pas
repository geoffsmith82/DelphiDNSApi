unit Test.DNS.Bunny;

interface

uses
  DUnitX.TestFramework,
  Test.DNS.Base,
  DNS.Bunny,
  DNS.Base;

type
  [TestFixture]
  TBunnyDnsTests = class(TDnsProviderTestsBase)
  protected
    function CreateClient: TBaseDNSProvider; override;
    function Capabilities: TDnsProviderCapabilities; override;
    function RootTestDomain: string; override;
  end;

implementation

uses
  ApiKeyStore; // or however you load secrets

function TBunnyDnsTests.CreateClient: TBaseDNSProvider;
begin
  Result := TBunnyDNSProvider.Create(TApiKeyStore.GetInstance.LoadApiKey('bunny_dns'));
end;

function TBunnyDnsTests.RootTestDomain: string;
begin
  Result := 'bunny68696465.site';
end;

function TBunnyDnsTests.Capabilities: TDnsProviderCapabilities;
begin
  Result := inherited;
  Result.SupportsSRV := True;
end;

initialization
  TDUnitX.RegisterTestFixture(TBunnyDnsTests);

end.

