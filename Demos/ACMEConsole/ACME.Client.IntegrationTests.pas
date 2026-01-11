unit ACME.Client.IntegrationTests;

interface

uses
  DUnitX.TestFramework,
  System.SysUtils,
  System.StrUtils,
  System.IOUtils,
  System.Generics.Collections,
  TaurusTLS,
  TaurusTLSHeaders_evp,
  ACME.Client,
  ACME.Client.Dns01,
  ACME.Client.Types,
  DNS.Azure,
  DNS.Base,
  DNS.Bunny,
  DNS.Cloudflare,
  DNS.DigitalOcean,
  DNS.Google,
  DNS.Route53,
  DNS.Vultr,
  ACME.Client.CmdLine

  {$IFDEF MSWINDOWS}
  , ACME.Client.WinCertStore
  {$ENDIF}
  , ApiKeyStore,
  ApiKeyStore.Windows
  ;

type
  [TestFixture]
  TAcmeIntegrationTests = class
  private
    FCreds: TDictionary<string, string>;
    FTempDir: string;

    procedure SetUpVultrCredentials;
    procedure CleanTempDir;
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;

//    [Test]
    procedure TestCertOnly_Vultr_Staging;

    {$IFDEF MSWINDOWS}
    [Test]
    procedure TestCertOnlyAndInstallToStore_Vultr_Staging;
    {$ENDIF}
  end;

implementation

// Copied from ACME.Client.CmdLine to avoid dependencies
function DefaultDirectoryUrl(const Opts: TAcmeConsoleOptions): string;
const
  ProdUrl = 'https://acme-v02.api.letsencrypt.org/directory';
  StagingUrl = 'https://acme-staging-v02.api.letsencrypt.org/directory';
begin
  if Opts.ServerUrl <> '' then
    Exit(Opts.ServerUrl);

  if Opts.Staging then
    Result := StagingUrl
  else
    Result := ProdUrl;
end;

function CredOrOpt(const OptValue: string; const Creds: TDictionary<string, string>; const Keys: array of string): string;
var
  K: string;
  V: string;
begin
  if OptValue <> '' then
    Exit(OptValue);

  for K in Keys do
    if Creds.TryGetValue(K.ToLower, V) then
      Exit(V);

  Result := '';
end;

function NormalizeProviderName(const S: string): string;
begin
  Result := S.Trim.ToLower;
  if Result.StartsWith('dns-') then
    Result := Result.Substring(4);
end;

function CreateDnsProvider(const Opts: TAcmeConsoleOptions; const Creds: TDictionary<string, string>): TBaseDNSProvider;
var
  Provider: string;
  ApiKey, ApiSecret: string;
  Region: string;
begin
  Provider := NormalizeProviderName(Opts.DnsProvider);
  if Provider = '' then
    raise Exception.Create('No DNS provider selected. Use --dns-provider <name> or --dns-<provider>.');

  if Provider = 'cloudflare' then
  begin
    ApiKey := CredOrOpt(Opts.ApiKey, Creds, ['dns_cloudflare_api_token', 'dns_cloudflare_api_key', 'api_token', 'api_key']);
    if ApiKey = '' then
      raise Exception.Create('Cloudflare requires an API token. Use --api-key or a credentials file key dns_cloudflare_api_token.');
    Result := TCloudflareDNSProvider.Create(ApiKey);
  end
  else if Provider = 'vultr' then
  begin
    ApiKey := CredOrOpt(Opts.ApiKey, Creds, ['dns_vultr_api_key', 'api_key']);
    if ApiKey = '' then
      raise Exception.Create('Vultr requires an API key. Use --api-key or dns_vultr_api_key in credentials file.');
    Result := TVultrDNSProvider.Create(ApiKey);
  end
  else if Provider = 'digitalocean' then
  begin
    ApiKey := CredOrOpt(Opts.ApiKey, Creds, ['dns_digitalocean_token', 'dns_digitalocean_api_token', 'api_token', 'api_key']);
    if ApiKey = '' then
      raise Exception.Create('DigitalOcean requires an API token. Use --api-key or dns_digitalocean_token in credentials file.');
    Result := TDigitalOceanDNSProvider.Create(ApiKey);
  end
  else if Provider = 'bunny' then
  begin
    ApiKey := CredOrOpt(Opts.ApiKey, Creds, ['dns_bunny_api_key', 'api_key']);
    if ApiKey = '' then
      raise Exception.Create('Bunny requires an API key. Use --api-key or dns_bunny_api_key in credentials file.');
    Result := TBunnyDNSProvider.Create(ApiKey);
  end
  else if Provider = 'route53' then
  begin
    Region := IfThen(Opts.AwsRegion <> '', Opts.AwsRegion, 'us-east-1');

    ApiKey := CredOrOpt(Opts.AwsAccessKey, Creds, ['aws_access_key_id', 'aws_access_key', 'dns_route53_aws_access_key_id']);
    ApiSecret := CredOrOpt(Opts.AwsSecretKey, Creds, ['aws_secret_access_key', 'aws_secret_key', 'dns_route53_aws_secret_access_key']);

    if ApiKey = '' then
      raise Exception.Create('Route53 requires --aws-access-key (or aws_access_key_id in credentials file).');
    if ApiSecret = '' then
      raise Exception.Create('Route53 requires --aws-secret-key (or aws_secret_access_key in credentials file).');

    Result := TRoute53DNSProvider.Create(ApiKey, ApiSecret, Region);
  end
  else if Provider = 'google' then
  begin
    var ProjectId := CredOrOpt(Opts.GoogleProjectId, Creds, ['google_project_id', 'dns_google_project_id']);
    var AccessToken := CredOrOpt(Opts.GoogleAccessToken, Creds, ['google_access_token', 'dns_google_access_token']);

    if ProjectId = '' then
      raise Exception.Create('Google requires --google-project-id (or google_project_id in credentials file).');
    if AccessToken = '' then
      raise Exception.Create('Google requires --google-access-token (or google_access_token in credentials file).');

    Result := TGoogleDNSProvider.Create(ProjectId, AccessToken);
  end
  else if Provider = 'azure' then
  begin
    var TenantId := CredOrOpt(Opts.AzureTenantId, Creds, ['azure_tenant_id', 'dns_azure_tenant_id']);
    var ClientId := CredOrOpt(Opts.AzureClientId, Creds, ['azure_client_id', 'dns_azure_client_id']);
    var ClientSecret := CredOrOpt(Opts.AzureClientSecret, Creds, ['azure_client_secret', 'dns_azure_client_secret']);
    var SubscriptionId := CredOrOpt(Opts.AzureSubscriptionId, Creds, ['azure_subscription_id', 'dns_azure_subscription_id']);
    var ResourceGroup := CredOrOpt(Opts.AzureResourceGroup, Creds, ['azure_resource_group', 'dns_azure_resource_group']);

    if TenantId = '' then
      raise Exception.Create('Azure requires --azure-tenant-id (or azure_tenant_id in credentials file).');
    if ClientId = '' then
      raise Exception.Create('Azure requires --azure-client-id (or azure_client_id in credentials file).');
    if ClientSecret = '' then
      raise Exception.Create('Azure requires --azure-client-secret (or azure_client_secret in credentials file).');
    if SubscriptionId = '' then
      raise Exception.Create('Azure requires --azure-subscription-id (or azure_subscription_id in credentials file).');
    if ResourceGroup = '' then
      raise Exception.Create('Azure requires --azure-resource-group (or azure_resource_group in credentials file).');

    Result := TAzureDNSProvider.Create(TenantId, ClientId, ClientSecret, SubscriptionId, ResourceGroup);
  end
  else
    raise Exception.CreateFmt('Unsupported DNS provider: %s', [Provider]);
end;

procedure EnsureDomainRecord(const DnsProvider: TBaseDNSProvider; const Domain: string; const TargetIP: string);
var
  ZoneName: string;
  Records: TObjectList<TDNSRecord>;
  DnsRecord: TDNSRecord;
  RecordFound: Boolean;
  NewRecord: TDNSRecord;
begin
  ZoneName := 'vltr68696465.site';
  // Check if A record exists for the domain
  Records := DnsProvider.ListRecords(ZoneName, drtA);
  try
    RecordFound := False;
    for DnsRecord in Records do
    begin
      if SameText(DnsRecord.Name, Domain) or
         (SameText(Copy(Domain, 1, Length(Domain) - Length(ZoneName) - 1), DnsRecord.Name)) then
      begin
        RecordFound := True;
        Break;
      end;
    end;

    if not RecordFound then
    begin
      // Create A record pointing to TargetIP (e.g., 127.0.0.1)
      NewRecord := TDNSRecord.Create;
      try
        NewRecord.Name := Copy(Domain, 1, Length(Domain) - Length(ZoneName) - 1); // e.g., 'testcert'
        if NewRecord.Name = '' then
          NewRecord.Name := '@'; // Root
        NewRecord.RecordType := drtA;
        NewRecord.Value := TargetIP;
        NewRecord.TTL := 600;

        DnsProvider.CreateRecord(ZoneName, NewRecord);
        Sleep(30000);
      finally
        FreeAndNil(NewRecord);
      end;
    end;
  finally
    FreeAndNil(Records);
  end;
end;

{ TAcmeIntegrationTests }

procedure TAcmeIntegrationTests.SetUpVultrCredentials;
begin
  // Expect environment variables for Vultr API key
  // In a real scenario, you might load from a secure config file
  FCreds.AddOrSetValue('dns_vultr_api_key', TApiKeyStore.GetInstance.LoadApiKey('vultr_dns'));
end;

procedure TAcmeIntegrationTests.CleanTempDir;
begin
  if DirectoryExists(FTempDir) then
    TDirectory.Delete(FTempDir, True);
end;

procedure TAcmeIntegrationTests.Setup;
begin
  FCreds := TDictionary<string, string>.Create;
  FTempDir := TPath.Combine(TPath.GetTempPath, 'AcmeConsoleTests_' + IntToStr(Random(10000)));
  ForceDirectories(FTempDir);

  SetUpVultrCredentials;

  // Verify OpenSSL is loaded
  if not Assigned(EVP_PKEY_CTX_new_id) then
    raise Exception.Create('OpenSSL library not loaded. Ensure OpenSSL DLLs (e.g., libcrypto-3.dll or libcrypto-1_1.dll) are in PATH or next to the executable.');
end;

procedure TAcmeIntegrationTests.TearDown;
begin
  FreeAndNil(FCreds);
  CleanTempDir;
end;

procedure TAcmeIntegrationTests.TestCertOnly_Vultr_Staging;
var
  Opts: TAcmeConsoleOptions;
  Creds: TDictionary<string, string>;
  Client: TAcmeClient;
  DnsProvider: TBaseDNSProvider;
  Solver: IAcmeChallengeSolver;
  CertPem, KeyPem, ChainPem: string;
  LiveDir: string;
begin
  Opts := TAcmeConsoleOptions.Create;
  try
    Opts.Command := 'certonly';
    Opts.DnsProvider := 'vultr';
    Opts.Staging := True; // Use staging to avoid hitting production rate limits
    Opts.Domains.Add('testcert.vltr68696465.site');
    Opts.Email := 'demo@tysontechnology.com.au'; // Use a dummy email for staging
    Opts.CredentialsFile := ''; // We'll pass creds via FCreds

    Creds := TDictionary<string, string>.Create;
    try
      for var Pair in FCreds do
        Creds.AddOrSetValue(Pair.Key, Pair.Value);

      DnsProvider := CreateDnsProvider(Opts, Creds);
      try
        // Ensure the domain has a DNS record (create dummy A record if needed)
        EnsureDomainRecord(DnsProvider, 'testcert.vltr68696465.site', '127.0.0.1');

        Solver := TAcmeDns01Solver.Create(DnsProvider);

        Client := TAcmeClient.Create(DefaultDirectoryUrl(Opts));
        try
          Client.StorageRoot := FTempDir;

          Client.AddSolver(Solver);

          Client.ObtainCertificate(
            Opts.Domains.ToArray,
            Opts.Email,
            CertPem, KeyPem, ChainPem,
            Opts.PreferredChallenge,
            Opts.Staging
          );

          // Verify certificate was issued
          Assert.IsNotEmpty(CertPem, 'Certificate PEM should not be empty');
          Assert.IsNotEmpty(KeyPem, 'Private key PEM should not be empty');
          Assert.IsNotEmpty(ChainPem, 'Chain PEM should not be empty');

          // Check that certs were saved to disk
          LiveDir := TPath.Combine(TPath.Combine(Client.StorageRoot, 'live'), Opts.Domains[0]);
          Assert.IsTrue(DirectoryExists(LiveDir), 'Live directory should exist');
          Assert.IsTrue(FileExists(TPath.Combine(LiveDir, 'cert.pem')), 'cert.pem should exist');
          Assert.IsTrue(FileExists(TPath.Combine(LiveDir, 'privkey.pem')), 'privkey.pem should exist');
          Assert.IsTrue(FileExists(TPath.Combine(LiveDir, 'chain.pem')), 'chain.pem should exist');
          Assert.IsTrue(FileExists(TPath.Combine(LiveDir, 'fullchain.pem')), 'fullchain.pem should exist');

        finally
          FreeAndNil(Client);
        end;
      finally
        FreeAndNil(DnsProvider);
      end;
    finally
      FreeAndNil(Creds);
    end;
  finally
    FreeAndNil(Opts);
  end;
end;

{$IFDEF MSWINDOWS}
procedure TAcmeIntegrationTests.TestCertOnlyAndInstallToStore_Vultr_Staging;
var
  Opts: TAcmeConsoleOptions;
  Creds: TDictionary<string, string>;
  Client: TAcmeClient;
  DnsProvider: TBaseDNSProvider;
  Solver: IAcmeChallengeSolver;
  CertPem, KeyPem, ChainPem: string;
  Thumbprint: string;
begin
  Opts := TAcmeConsoleOptions.Create;
  try
    Opts.Command := 'certonly';
    Opts.DnsProvider := 'vultr';
    Opts.Staging := True;
    Opts.Domains.Add('testcert.tyson.technology');
    Opts.Email := 'demo@tysontechnology.com.au';
    Opts.InstallToWindowsStore := True;
    Opts.WindowsStoreLocation := 'localmachine';
    Opts.WindowsStoreName := 'Web Hosting';

    Creds := TDictionary<string, string>.Create;
    try
      for var Pair in FCreds do
        Creds.AddOrSetValue(Pair.Key, Pair.Value);

      DnsProvider := CreateDnsProvider(Opts, Creds);
      try
        // Ensure the domain has a DNS record (create dummy A record if needed)
//        EnsureDomainRecord(DnsProvider, 'testcert.tyson.technology', '127.0.0.1');

        Solver := TAcmeDns01Solver.Create(DnsProvider);

        Client := TAcmeClient.Create(DefaultDirectoryUrl(Opts));
        try
          Client.StorageRoot := FTempDir;

          Client.AddSolver(Solver);

          Client.ObtainCertificate(
            Opts.Domains.ToArray,
            Opts.Email,
            CertPem, KeyPem, ChainPem,
            Opts.PreferredChallenge,
            Opts.Staging
          );

          // Install to Windows store
          Thumbprint := InstallCertificatePemToWindowsStore(
            CertPem,
            KeyPem,
            Opts.WindowsStoreName,
            wslLocalMachine,
            Opts.WindowsPfxPassword,
            Opts.WindowsExportableKey,
            Opts.Domains[0] // Use the primary domain as friendly name
          );

          // Verify installation
          Assert.IsNotEmpty(Thumbprint, 'Thumbprint should not be empty after installation');

        finally
          FreeAndNil(Client);
        end;
      finally
        FreeAndNil(DnsProvider);
      end;
    finally
      FreeAndNil(Creds);
    end;
  finally
    FreeAndNil(Opts);
  end;
end;
{$ENDIF}

initialization
  TDUnitX.RegisterTestFixture(TAcmeIntegrationTests);

end.