unit Test.DNS.Vultr;

interface

uses
  DUnitX.TestFramework,
  Test.DNS.Base,
  DNS.Vultr,
  DNS.Base;

type
  [TestFixture]
  TVultrDnsTests = class(TDnsProviderTestsBase)
  protected
    function CreateClient: TBaseDNSProvider; override;
    function Capabilities: TDnsProviderCapabilities; override;
    function RootTestDomain: string; override;
  end;

implementation

uses
  ApiKeyStore; // or however you load secrets

function TVultrDnsTests.CreateClient: TBaseDNSProvider;
begin
  Result := TVultrDNSProvider.Create(TApiKeyStore.GetInstance.LoadApiKey('vultr_dns'));
end;

function TVultrDnsTests.RootTestDomain: string;
begin
  Result := 'vltr68696465.site';
end;

function TVultrDnsTests.Capabilities: TDnsProviderCapabilities;
begin
  Result := inherited;
  Result.SupportsSRV := True;
end;

initialization
  TDUnitX.RegisterTestFixture(TVultrDnsTests);

end.

