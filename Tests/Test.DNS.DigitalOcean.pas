unit Test.DNS.DigitalOcean;

interface

uses
  DUnitX.TestFramework,
  Test.DNS.Base,
  DNS.DigitalOcean,
  DNS.Base;

type
  [TestFixture]
  TDigitalOceanDnsTests = class(TDnsProviderTestsBase)
  protected
    function CreateClient: TBaseDNSProvider; override;
    function Capabilities: TDnsProviderCapabilities; override;
    function RootTestDomain: string; override;
  end;

implementation

uses
  ApiKeyStore; // or however you load secrets

function TDigitalOceanDnsTests.CreateClient: TBaseDNSProvider;
begin
  Result := TDigitalOceanDNSProvider.Create(TApiKeyStore.GetInstance.LoadApiKey('digitalocean_dns'));
end;

function TDigitalOceanDnsTests.RootTestDomain: string;
begin
  Result := 'do68696465.site';
end;

function TDigitalOceanDnsTests.Capabilities: TDnsProviderCapabilities;
begin
  Result := inherited;
  Result.SupportsSRV := True;
end;

initialization
  TDUnitX.RegisterTestFixture(TDigitalOceanDnsTests);

end.
