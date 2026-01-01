unit ACME.Client.CmdLine;

interface

procedure Run;

implementation

uses
  System.SysUtils,
  System.IOUtils,
  System.Classes,
  System.StrUtils,
  System.Generics.Collections,
  System.JSON,
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
  DNS.Vultr;

type
  TAcmeConsoleOptions = class
  public
    Command: string;

    ShowHelp: Boolean;
    ShowVersion: Boolean;

    ServerUrl: string;
    Staging: Boolean;

    Email: string;
    Domains: TList<string>;

    PreferredChallenge: TChallengeType;

    DnsProvider: string;
    CredentialsFile: string;

    ApiKey: string;
    ApiSecret: string;

    AwsAccessKey: string;
    AwsSecretKey: string;
    AwsRegion: string;

    GoogleProjectId: string;
    GoogleAccessToken: string;

    AzureTenantId: string;
    AzureClientId: string;
    AzureClientSecret: string;
    AzureSubscriptionId: string;
    AzureResourceGroup: string;

    ConfigDir: string;
    AccountFile: string;
    OutputDir: string;

    constructor Create;
    destructor Destroy; override;
  end;

constructor TAcmeConsoleOptions.Create;
begin
  inherited Create;
  Domains := TList<string>.Create;
  PreferredChallenge := ctDns01;
end;

destructor TAcmeConsoleOptions.Destroy;
begin
  FreeAndNil(Domains);
  inherited;
end;

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

function DefaultStorageRoot: string;
begin
  {$IFDEF MSWINDOWS}
    Result := TPath.Combine(TPath.GetPublicPath, 'AcmeClient');
  {$ELSE}
    Result := '/etc/acme-client';
  {$ENDIF}
end;

function EffectiveStorageRoot(const Opts: TAcmeConsoleOptions): string;
begin
  if Opts.ConfigDir <> '' then
    Result := Opts.ConfigDir
  else
    Result := DefaultStorageRoot;
end;

procedure PrintHelp;
begin
  Writeln('ACMEDemoConsole - certbot-like ACME client (DNS-01 only for now)');
  Writeln;
  Writeln('Usage:');
  Writeln('  acmeconsole certonly [options] -d <domain> [-d <domain> ...]');
  Writeln('  acmeconsole certificates [--config-dir <dir>]');
  Writeln;
  Writeln('General options:');
  Writeln('  -h, --help                 Show help');
  Writeln('  --version                  Show version');
  Writeln('  --server <url>             Override ACME directory URL');
  Writeln('  --staging                  Use Let''s Encrypt staging directory');
  Writeln('  --config-dir <dir>         Storage root (like certbot config dir)');
  Writeln('  --account-file <file>      Account JSON file path');
  Writeln;
  Writeln('Certificate request options:');
  Writeln('  -d, --domain <domain>      Domain to include (repeatable)');
  Writeln('  -m, --email <email>        Account email (recommended)');
  Writeln('  --preferred-challenges dns|http');
  Writeln('                             Defaults to dns');
  Writeln('  --output-dir <dir>         Also copy PEMs into this folder');
  Writeln;
  Writeln('DNS provider selection (pick one):');
  Writeln('  --dns-provider <name>      cloudflare|vultr|digitalocean|bunny|route53|google|azure');
  Writeln('  --dns-cloudflare           Alias for --dns-provider cloudflare');
  Writeln('  --dns-vultr                Alias for --dns-provider vultr');
  Writeln('  --dns-digitalocean         Alias for --dns-provider digitalocean');
  Writeln('  --dns-bunny                Alias for --dns-provider bunny');
  Writeln('  --dns-route53              Alias for --dns-provider route53');
  Writeln('  --dns-google               Alias for --dns-provider google');
  Writeln('  --dns-azure                Alias for --dns-provider azure');
  Writeln;
  Writeln('DNS credentials:');
  Writeln('  --dns-credentials <file>   Key/value file (like certbot dns plugins)');
  Writeln('  --dns-<provider>-credentials <file>');
  Writeln('                             Convenience flag: selects provider too');
  Writeln('  --api-key <value>          For providers with token-based auth');
  Writeln('  --api-secret <value>       Some providers require a secret');
  Writeln;
  Writeln('Examples:');
  Writeln('  acmeconsole certonly --dns-cloudflare --api-key <token> -d example.com -m you@example.com --staging');
  Writeln('  acmeconsole certonly --dns-provider vultr --dns-credentials vultr.ini -d example.com -m you@example.com');
end;

function SplitOption(const Arg: string; out Name, Value: string): Boolean;
var
  P: Integer;
begin
  Name := '';
  Value := '';
  if not Arg.StartsWith('--') then
    Exit(False);

  P := Arg.IndexOf('=');
  if P < 0 then
    Exit(False);

  Name := Arg.Substring(0, P);
  Value := Arg.Substring(P + 1);
  Result := True;
end;

function StripQuotes(const S: string): string;
begin
  Result := S.Trim;
  if (Length(Result) >= 2) and
     (((Result[1] = '"') and (Result[Length(Result)] = '"')) or
      ((Result[1] = '''') and (Result[Length(Result)] = ''''))) then
    Result := Result.Substring(1, Length(Result) - 2);
end;

function LoadCredentialsFile(const FileName: string): TDictionary<string, string>;
var
  Lines: TStringList;
  Line, TrimmedLine: string;
  Key, Value: string;
  P: Integer;
begin
  Result := TDictionary<string, string>.Create;

  if FileName = '' then
    Exit;

  if not FileExists(FileName) then
    raise Exception.CreateFmt('Credentials file not found: %s', [FileName]);

  Lines := TStringList.Create;
  try
    Lines.LoadFromFile(FileName, TEncoding.UTF8);

    for Line in Lines do
    begin
      TrimmedLine := Line.Trim;
      if (TrimmedLine = '') or TrimmedLine.StartsWith('#') or TrimmedLine.StartsWith(';') then
        Continue;

      P := TrimmedLine.IndexOf('=');
      if P < 0 then
        Continue;

      Key := TrimmedLine.Substring(0, P).Trim.ToLower;
      Value := StripQuotes(TrimmedLine.Substring(P + 1));

      if Key <> '' then
        Result.AddOrSetValue(Key, Value);
    end;
  finally
    FreeAndNil(Lines);
  end;
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

function ParseOptions(const Opts: TAcmeConsoleOptions; out Error: string): Boolean;
var
  I: Integer;
  Arg, Name, Value: string;

  procedure NeedValue;
  begin
    if I >= ParamCount then
      raise Exception.CreateFmt('Missing value after %s', [Arg]);
    Inc(I);
    Value := ParamStr(I);
  end;

  procedure SetProvider(const Provider: string);
  begin
    Opts.DnsProvider := NormalizeProviderName(Provider);
  end;

begin
  Result := False;
  Error := '';

  try
    I := 1;
    while I <= ParamCount do
    begin
      Arg := ParamStr(I);

      if SplitOption(Arg, Name, Value) then
        Arg := Name
      else
        Value := '';

      if (Arg = '-h') or (Arg = '--help') then
        Opts.ShowHelp := True
      else if Arg = '--version' then
        Opts.ShowVersion := True
      else if (not Arg.StartsWith('-')) and (Opts.Command = '') then
        Opts.Command := Arg
      else if (Arg = '-d') or (Arg = '--domain') or (Arg = '--domains') then
      begin
        if Value = '' then NeedValue;
        Opts.Domains.Add(Value);
      end
      else if (Arg = '-m') or (Arg = '--email') then
      begin
        if Value = '' then NeedValue;
        Opts.Email := Value;
      end
      else if Arg = '--server' then
      begin
        if Value = '' then NeedValue;
        Opts.ServerUrl := Value;
      end
      else if Arg = '--staging' then
        Opts.Staging := True
      else if Arg = '--preferred-challenges' then
      begin
        if Value = '' then NeedValue;
        Value := Value.Trim.ToLower;
        if (Value = 'dns') or (Value = 'dns-01') then
          Opts.PreferredChallenge := ctDns01
        else if (Value = 'http') or (Value = 'http-01') then
          Opts.PreferredChallenge := ctHttp01
        else
          raise Exception.CreateFmt('Unknown --preferred-challenges value: %s', [Value]);
      end
      else if (Arg = '--dns-provider') then
      begin
        if Value = '' then NeedValue;
        SetProvider(Value);
      end
      else if Arg = '--dns-credentials' then
      begin
        if Value = '' then NeedValue;
        Opts.CredentialsFile := Value;
      end
      else if Arg = '--dns-cloudflare-credentials' then
      begin
        SetProvider('cloudflare');
        if Value = '' then NeedValue;
        Opts.CredentialsFile := Value;
      end
      else if Arg = '--dns-vultr-credentials' then
      begin
        SetProvider('vultr');
        if Value = '' then NeedValue;
        Opts.CredentialsFile := Value;
      end
      else if Arg = '--dns-digitalocean-credentials' then
      begin
        SetProvider('digitalocean');
        if Value = '' then NeedValue;
        Opts.CredentialsFile := Value;
      end
      else if Arg = '--dns-bunny-credentials' then
      begin
        SetProvider('bunny');
        if Value = '' then NeedValue;
        Opts.CredentialsFile := Value;
      end
      else if Arg = '--dns-route53-credentials' then
      begin
        SetProvider('route53');
        if Value = '' then NeedValue;
        Opts.CredentialsFile := Value;
      end
      else if Arg = '--dns-google-credentials' then
      begin
        SetProvider('google');
        if Value = '' then NeedValue;
        Opts.CredentialsFile := Value;
      end
      else if Arg = '--dns-azure-credentials' then
      begin
        SetProvider('azure');
        if Value = '' then NeedValue;
        Opts.CredentialsFile := Value;
      end
      else if (Arg = '--agree-tos') or (Arg = '--non-interactive') or (Arg = '--noninteractive') then
      begin
        // accepted for certbot-style compatibility (no prompting in this demo)
      end
      else if Arg = '--api-key' then
      begin
        if Value = '' then NeedValue;
        Opts.ApiKey := Value;
      end
      else if Arg = '--api-secret' then
      begin
        if Value = '' then NeedValue;
        Opts.ApiSecret := Value;
      end
      else if Arg = '--aws-access-key' then
      begin
        if Value = '' then NeedValue;
        Opts.AwsAccessKey := Value;
      end
      else if Arg = '--aws-secret-key' then
      begin
        if Value = '' then NeedValue;
        Opts.AwsSecretKey := Value;
      end
      else if Arg = '--aws-region' then
      begin
        if Value = '' then NeedValue;
        Opts.AwsRegion := Value;
      end
      else if Arg = '--google-project-id' then
      begin
        if Value = '' then NeedValue;
        Opts.GoogleProjectId := Value;
      end
      else if Arg = '--google-access-token' then
      begin
        if Value = '' then NeedValue;
        Opts.GoogleAccessToken := Value;
      end
      else if Arg = '--azure-tenant-id' then
      begin
        if Value = '' then NeedValue;
        Opts.AzureTenantId := Value;
      end
      else if Arg = '--azure-client-id' then
      begin
        if Value = '' then NeedValue;
        Opts.AzureClientId := Value;
      end
      else if Arg = '--azure-client-secret' then
      begin
        if Value = '' then NeedValue;
        Opts.AzureClientSecret := Value;
      end
      else if Arg = '--azure-subscription-id' then
      begin
        if Value = '' then NeedValue;
        Opts.AzureSubscriptionId := Value;
      end
      else if Arg = '--azure-resource-group' then
      begin
        if Value = '' then NeedValue;
        Opts.AzureResourceGroup := Value;
      end
      else if Arg = '--config-dir' then
      begin
        if Value = '' then NeedValue;
        Opts.ConfigDir := Value;
      end
      else if Arg = '--account-file' then
      begin
        if Value = '' then NeedValue;
        Opts.AccountFile := Value;
      end
      else if Arg = '--output-dir' then
      begin
        if Value = '' then NeedValue;
        Opts.OutputDir := Value;
      end
      else if Arg = '--dns-cloudflare' then
        SetProvider('cloudflare')
      else if Arg = '--dns-vultr' then
        SetProvider('vultr')
      else if Arg = '--dns-digitalocean' then
        SetProvider('digitalocean')
      else if Arg = '--dns-bunny' then
        SetProvider('bunny')
      else if Arg = '--dns-route53' then
        SetProvider('route53')
      else if Arg = '--dns-google' then
        SetProvider('google')
      else if Arg = '--dns-azure' then
        SetProvider('azure')
      else
        raise Exception.CreateFmt('Unknown argument: %s', [ParamStr(I)]);

      Inc(I);
    end;

    Result := True;
  except
    on E: Exception do
    begin
      Error := E.Message;
      Result := False;
    end;
  end;
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

procedure CmdCertOnly(const Opts: TAcmeConsoleOptions);
var
  Creds: TDictionary<string, string>;
  Client: TAcmeClient;
  DnsProvider: TBaseDNSProvider;
  Solver: IAcmeChallengeSolver;
  CertPem, KeyPem, ChainPem: string;
  StorageRoot, LiveDir: string;
begin
  if Opts.Domains.Count = 0 then
    raise Exception.Create('No domains specified. Use -d <domain> (repeatable).');

  if Opts.PreferredChallenge <> ctDns01 then
    raise Exception.Create('Only DNS-01 is implemented in this console demo currently. Use --preferred-challenges dns.');

  Creds := LoadCredentialsFile(Opts.CredentialsFile);
  try
    DnsProvider := CreateDnsProvider(Opts, Creds);
    try
      Solver := TAcmeDns01Solver.Create(DnsProvider);

      Client := TAcmeClient.Create(DefaultDirectoryUrl(Opts));
      try
        if Opts.ConfigDir <> '' then
          Client.StorageRoot := Opts.ConfigDir;
        if Opts.AccountFile <> '' then
          Client.AccountFile := Opts.AccountFile;
        if Opts.DnsProvider <> '' then
          Client.DnsProviderName := Opts.DnsProvider;

        Client.AddSolver(Solver);

        Client.ObtainCertificate(
          Opts.Domains.ToArray,
          Opts.Email,
          CertPem, KeyPem, ChainPem,
          Opts.PreferredChallenge,
          Opts.Staging
        );

        StorageRoot := EffectiveStorageRoot(Opts);
        LiveDir := TPath.Combine(TPath.Combine(StorageRoot, 'live'), Opts.Domains[0]);

        Writeln('Success. Certificate stored under: ', LiveDir);

      finally
        FreeAndNil(Client);
      end;
    finally
      FreeAndNil(DnsProvider);
    end;
  finally
    FreeAndNil(Creds);
  end;
end;

procedure CmdCertificates(const Opts: TAcmeConsoleOptions);
var
  StorageRoot, LiveRoot, RenewalRoot: string;
  CertDirs: TArray<string>;
  CertDir: string;
  Name: string;
  RenewalFile: string;
  JsonText: string;
  J: TJSONObject;
  Domains: TJSONArray;
  DomainList: string;
  I: Integer;
  LastRenewed: string;
  AuthMethod: string;
  DnsProvider: string;
begin
  StorageRoot := EffectiveStorageRoot(Opts);
  LiveRoot := TPath.Combine(StorageRoot, 'live');
  RenewalRoot := TPath.Combine(StorageRoot, 'renewal');

  if not DirectoryExists(LiveRoot) then
  begin
    Writeln('No certificates found (missing directory: ', LiveRoot, ')');
    Exit;
  end;

  CertDirs := TDirectory.GetDirectories(LiveRoot);
  if Length(CertDirs) = 0 then
  begin
    Writeln('No certificates found in: ', LiveRoot);
    Exit;
  end;

  for CertDir in CertDirs do
  begin
    Name := TPath.GetFileName(CertDir);
    RenewalFile := TPath.Combine(RenewalRoot, Name + '.json');

    if FileExists(RenewalFile) then
    begin
      JsonText := TFile.ReadAllText(RenewalFile, TEncoding.UTF8);
      J := TJSONObject.ParseJSONValue(JsonText) as TJSONObject;
      try
        DomainList := '';
        Domains := J.GetValue('domains') as TJSONArray;
        if Domains <> nil then
        begin
          for I := 0 to Domains.Count - 1 do
          begin
            if DomainList <> '' then
              DomainList := DomainList + ', ';
            DomainList := DomainList + Domains.Items[I].Value;
          end;
        end;

        Writeln(Name, ' (', DomainList, ')');

        if J.TryGetValue<string>('last_renewed', LastRenewed) and (LastRenewed <> '') then
          Writeln('  last_renewed: ', LastRenewed);

        if J.TryGetValue<string>('auth_method', AuthMethod) and (AuthMethod <> '') then
          Writeln('  auth_method : ', AuthMethod);

        if J.TryGetValue<string>('dns_provider', DnsProvider) and (DnsProvider <> '') then
          Writeln('  dns_provider: ', DnsProvider);

      finally
        FreeAndNil(J);
      end;
    end
    else
      Writeln(Name);
  end;
end;

function EnsureCommand(const Opts: TAcmeConsoleOptions): string;
begin
  Result := Opts.Command.Trim.ToLower;
  if Result = '' then
    Result := 'help';
end;

procedure Run;
begin
  try
    var Opts := TAcmeConsoleOptions.Create;
    try
      var Error: string;
      if not ParseOptions(Opts, Error) then
      begin
        Writeln('Error: ', Error);
        Writeln;
        PrintHelp;
        ExitCode := 1;
        Exit;
      end;

      if Opts.ShowHelp then
      begin
        PrintHelp;
        ExitCode := 0;
        Exit;
      end;

      if Opts.ShowVersion then
      begin
        Writeln('ACMEDemoConsole 0.1');
        ExitCode := 0;
        Exit;
      end;

      var Cmd := EnsureCommand(Opts);

      if (Cmd = 'help') or (Cmd = '--help') then
      begin
        PrintHelp;
        ExitCode := 0;
        Exit;
      end
      else if Cmd = 'certonly' then
      begin
        CmdCertOnly(Opts);
        ExitCode := 0;
        Exit;
      end
      else if (Cmd = 'certificates') or (Cmd = 'certs') then
      begin
        CmdCertificates(Opts);
        ExitCode := 0;
        Exit;
      end
      else
      begin
        Writeln('Unknown command: ', Opts.Command);
        Writeln;
        PrintHelp;
        ExitCode := 1;
        Exit;
      end;

    finally
      FreeAndNil(Opts);
    end;
  except
    on E: Exception do
    begin
      Writeln(E.ClassName, ': ', E.Message);
      ExitCode := 1;
    end;
  end;
end;

end.
