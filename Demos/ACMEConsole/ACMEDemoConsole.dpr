program ACMEDemoConsole;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  System.IOUtils,
  ACME.Client in 'ACME.Client.pas',
  DNS.Azure in '..\..\Source\DNS.Azure.pas',
  DNS.Base in '..\..\Source\DNS.Base.pas',
  DNS.Bunny in '..\..\Source\DNS.Bunny.pas',
  DNS.Cloudflare in '..\..\Source\DNS.Cloudflare.pas',
  DNS.DigitalOcean in '..\..\Source\DNS.DigitalOcean.pas',
  DNS.Google in '..\..\Source\DNS.Google.pas',
  DNS.Helpers in '..\..\Source\DNS.Helpers.pas',
  DNS.Route53 in '..\..\Source\DNS.Route53.pas',
  DNS.Vultr in '..\..\Source\DNS.Vultr.pas',
  ACME.TaurusCrypto in 'ACME.TaurusCrypto.pas',
  ACME.Client.Dns01 in 'ACME.Client.Dns01.pas',
  ACME.Client.Types in 'ACME.Client.Types.pas',
  ACME.Client.Http01 in 'ACME.Client.Http01.pas';

var
  Client      : TAcmeClient;
  DnsProvider : TBaseDNSProvider;
  DnsSolver   : IAcmeChallengeSolver;
  {HttpInstaller: IAcmeHttpChallengeInstaller;
  HttpSolver: IAcmeChallengeSolver;}
  CertPem, KeyPem, ChainPem: string;
begin
  try
    // Pick provider and API credentials (from config, env, etc.)
    DnsProvider := TVultrDNSProvider.Create('YOUR_API_KEY_HERE');
    try
      DnsSolver := TAcmeDns01Solver.Create(DnsProvider);
      // HttpInstaller := TWebRootInstaller.Create('/var/www/...');
      // HttpSolver := TAcmeHttp01Solver.Create(HttpInstaller);

      Client := TAcmeClient.Create('https://acme-staging-v02.api.letsencrypt.org/directory');
      try
        Client.AddSolver(DnsSolver);
        // Client.AddSolver(HttpSolver); // So HTTP-01 is also available

        Client.ObtainCertificate(
          ['example.com', 'www.example.com'],
          'you@example.com',
          CertPem, KeyPem, ChainPem,
          ctDns01,  // prefer DNS-01
          True      // Use staging while testing
        );

        // Save PEMs to disk
        TFile.WriteAllText('cert.pem', CertPem, TEncoding.UTF8);
        TFile.WriteAllText('privkey.pem', KeyPem, TEncoding.UTF8);
        TFile.WriteAllText('chain.pem', ChainPem, TEncoding.UTF8);
      finally
        Client.Free;
      end;
    finally
      DnsProvider.Free;
    end;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.

