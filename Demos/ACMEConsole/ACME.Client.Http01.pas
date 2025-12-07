unit ACME.Client.Http01;

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  ACME.Client.Types;

type
  // HTTP-01 solver using external installer
  TAcmeHttp01Solver = class(TInterfacedObject, IAcmeChallengeSolver)
  private
    FInstaller: IAcmeHttpChallengeInstaller;
  public
    constructor Create(const AInstaller: IAcmeHttpChallengeInstaller);
    function CanSolve(const ChallengeType: TChallengeType): Boolean;
    procedure Solve(const Domain: string; const Challenge: TAcmeChallenge; const KeyAuthorization: string);
    procedure Cleanup(const Domain: string; const Challenge: TAcmeChallenge);
  end;

implementation

{ TAcmeHttp01Solver }

constructor TAcmeHttp01Solver.Create(const AInstaller: IAcmeHttpChallengeInstaller);
begin
  inherited Create;
  FInstaller := AInstaller;
end;

function TAcmeHttp01Solver.CanSolve(const ChallengeType: TChallengeType): Boolean;
begin
  Result := ChallengeType = ctHttp01;
end;

procedure TAcmeHttp01Solver.Solve(const Domain: string; const Challenge: TAcmeChallenge;
  const KeyAuthorization: string);
begin
  // For HTTP-01, ACME will GET:
  // http://<domain>/.well-known/acme-challenge/<token>
  // And expect body == keyAuthorization
  FInstaller.Install(Domain, Challenge.Token, KeyAuthorization);
end;

procedure TAcmeHttp01Solver.Cleanup(const Domain: string; const Challenge: TAcmeChallenge);
begin
  FInstaller.Cleanup(Domain, Challenge.Token);
end;

end.
