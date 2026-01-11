unit Test.DNS.Route53;

interface

uses
  DUnitX.TestFramework,
  System.SysUtils,
  Test.DNS.Base,
  ApiKeyStore,
  DNS.Base,
  DNS.Route53;

type
  [TestFixture]
  TRoute53DnsTests = class(TDnsProviderTestsBase)
  private
    function CreateClient: TBaseDNSProvider; override;
    function RootTestDomain: string; override;
  end;

implementation

function TRoute53DnsTests.RootTestDomain: string;
begin
  Result := 'teasfdsdstd.site';
end;

function TRoute53DnsTests.CreateClient: TBaseDNSProvider;
var
  ks : TApiKeyStore;
  AccessKey: string;
  SecretKey: string;
  Region: string;
begin
  ks := TApiKeyStore.GetInstance;

  // Prefer environment variables, fall back to ApiKeyStore
  AccessKey := GetEnvironmentVariable('AWS_ACCESS_KEY_ID_dns');
  if AccessKey = '' then
    AccessKey := GetEnvironmentVariable('AWS_ACCESS_KEY_ID');
  if AccessKey = '' then
    AccessKey := ks.LoadApiKey('AWS_ACCESS_KEY_ID_dns');

  SecretKey := GetEnvironmentVariable('AWS_SECRET_ACCESS_KEY_dns');
  if SecretKey = '' then
    SecretKey := GetEnvironmentVariable('AWS_SECRET_ACCESS_KEY');
  if SecretKey = '' then
    SecretKey := ks.LoadApiKey('AWS_SECRET_ACCESS_KEY_dns');

  Region := GetEnvironmentVariable('AWS_REGION');
  if Region = '' then
    Region := GetEnvironmentVariable('AWS_DEFAULT_REGION');
  if Region = '' then
    Region := 'us-east-1';

  if (AccessKey = '') or (SecretKey = '') then
    raise Exception.Create('AWS credentials not configured (set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)');

  Result := TRoute53DNSProvider.Create(AccessKey, SecretKey, Region);
end;

initialization
  TDUnitX.RegisterTestFixture(TRoute53DnsTests);

end.

