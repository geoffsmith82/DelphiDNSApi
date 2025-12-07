unit ACME.Client.Types;

interface

type
  TChallengeType = (ctDns01, ctHttp01);

  // Minimal model types – extend as needed
  TAcmeDirectory = record
    NewNonceUrl   : string;
    NewAccountUrl : string;
    NewOrderUrl   : string;
  end;

  TAcmeAuthorizationStatus = (asPending, asValid, asInvalid);

  TAcmeChallenge = record
    ChallengeType     : TChallengeType;  // 'dns-01' or 'http-01'
    Url               : string;  // challenge URL
    Token             : string;  // token from server
  end;

  TAcmeAuthorization = record
    Identifier        : string;  // domain name
    Status            : TAcmeAuthorizationStatus;
    Challenges        : TArray<TAcmeChallenge>;
  end;

  // Simple abstraction for DNS TXT management, backed by DelphiDNSApi
  IDnsTxtManager = interface
    ['{C2E54359-2A28-4AEC-8EF4-7A0AF9F79F47}']
    procedure PutTxtRecord(const Domain, Name, Value: string; TTL: Integer = 60);
    procedure DeleteTxtRecord(const Domain, Name: string);
  end;

  // HTTP-01 hook – your app can implement file writing, embedded HTTP server, etc
  IAcmeHttpChallengeInstaller = interface
    ['{EEB97F99-DF74-4E5D-884B-12531A4EEBEB}']
    procedure Install(const Domain, Token, KeyAuthorization: string);
    procedure Cleanup(const Domain, Token: string);
  end;

  // Common interface for all challenge solvers
  IAcmeChallengeSolver = interface
    ['{C39AF4B2-7C9D-4C53-9B72-0A4842BDEFFD}']
    function CanSolve(const ChallengeType: TChallengeType): Boolean;
    procedure Solve(const Domain: string; const Challenge: TAcmeChallenge;
      const KeyAuthorization: string);
    procedure Cleanup(const Domain: string; const Challenge: TAcmeChallenge);
  end;


implementation

end.
