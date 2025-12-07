unit ACME.Client;

interface

uses
  System.SysUtils,
  System.Classes,
  System.Generics.Collections,
  System.Net.HttpClient,
  System.Net.URLClient,
  System.JSON,
  ACME.Client.Types;

type






  // High-level ACME client
  TAcmeClient = class
  private
    FHttp       : THTTPClient;
    FDirectory  : TAcmeDirectory;
    FDirectoryUrl: string;
    FSolvers    : TList<IAcmeChallengeSolver>;
    FAccountKey : string; // PEM / JWK / whatever you decide
    procedure LoadDirectory;
    function NewNonce: string;

    function JwsPost(const Url: string; const Payload: TJSONObject): TJSONObject;
    function GetAuthorizationsForOrder(const OrderObj: TJSONObject): TArray<TAcmeAuthorization>;

    function ComputeKeyAuthorization(const Token: string): string;
    function ComputeDns01TxtValue(const KeyAuthorization: string): string;

    procedure ValidateAuthorizations(const Auths: TArray<TAcmeAuthorization>; PrefType: TChallengeType);
  public
    constructor Create(const ADirectoryUrl: string = 'https://acme-v02.api.letsencrypt.org/directory');
    destructor Destroy; override;

    procedure AddSolver(const Solver: IAcmeChallengeSolver);

    procedure RegisterOrLoadAccount(const Email: string; const AccountFile: string);

    // High-level: obtain cert + key & full chain as PEM
    procedure ObtainCertificate(const Domains: TArray<string>; const Email: string;
      out CertificatePem, PrivateKeyPem, ChainPem: string;
      PrefType: TChallengeType = ctDns01;
      UseStaging: Boolean = True);
  end;

implementation

uses
  System.Hash,
  System.NetEncoding,
  System.Math;

{ Helper functions }

function Base64UrlEncode(const Bytes: TBytes): string;
begin
  Result := TNetEncoding.Base64.EncodeBytesToString(Bytes);
  Result := Result.Replace('+', '-').Replace('/', '_').Replace('=', '');
end;

function ComputeDns01TxtValue(const KeyAuthorization: string): string;
var
  HashBytes: TBytes;
begin
  HashBytes := THashSHA2.GetHashBytes(KeyAuthorization);
  Result := Base64UrlEncode(HashBytes);
end;





{ TAcmeClient }

constructor TAcmeClient.Create(const ADirectoryUrl: string);
begin
  inherited Create;
  FHttp := THTTPClient.Create;
  FDirectoryUrl := ADirectoryUrl;
  FSolvers := TList<IAcmeChallengeSolver>.Create;
  LoadDirectory;
end;

destructor TAcmeClient.Destroy;
begin
  FreeAndNil(FSolvers);
  FreeAndNil(FHttp);
  inherited;
end;

procedure TAcmeClient.AddSolver(const Solver: IAcmeChallengeSolver);
begin
  FSolvers.Add(Solver);
end;

procedure TAcmeClient.LoadDirectory;
var
  Resp: IHTTPResponse;
  Obj, Meta: TJSONObject;
begin
  Resp := FHttp.Get(FDirectoryUrl);
  Obj := TJSONObject.ParseJSONValue(Resp.ContentAsString) as TJSONObject;
  try
    Meta := Obj.GetValue('meta') as TJSONObject;
    FDirectory.NewNonceUrl   := Obj.GetValue('newNonce').Value;
    FDirectory.NewAccountUrl := Obj.GetValue('newAccount').Value;
    FDirectory.NewOrderUrl   := Obj.GetValue('newOrder').Value;
  finally
    Obj.Free;
  end;
end;

function TAcmeClient.NewNonce: string;
var
  Resp: IHTTPResponse;
begin
  Resp := FHttp.Head(FDirectory.NewNonceUrl);
  Result := Resp.HeaderValue['Replay-Nonce'];
end;

function TAcmeClient.JwsPost(const Url: string; const Payload: TJSONObject): TJSONObject;
begin
  // TODO:
  //  1. Build JWS header with kid/jwk, nonce, url, alg
  //  2. Base64Url encode header & payload
  //  3. Sign with account key (OpenSSL / CryptoAPI / etc)
  //  4. POST {"protected": "...","payload": "...","signature":"..."}
  //  5. Return parsed JSON object
  Result := nil;
  raise ENotImplemented.Create('JwsPost is not implemented yet');
end;

function TAcmeClient.GetAuthorizationsForOrder(
  const OrderObj: TJSONObject): TArray<TAcmeAuthorization>;
begin
  // TODO: follow "authorizations" URLs in order object and build records
  SetLength(Result, 0);
end;

function TAcmeClient.ComputeKeyAuthorization(const Token: string): string;
var
  ThumbprintBytes: TBytes;
begin
  // TODO:
  //  - Build JWK from account key
  //  - Compute SHA-256 over canonical JWK JSON
  //  - Base64Url encode → thumbprint
  // For now, just stub:
  ThumbprintBytes := TEncoding.UTF8.GetBytes('TODO-thumbprint');
  Result := Token + '.' + Base64UrlEncode(ThumbprintBytes);
end;

function TAcmeClient.ComputeDns01TxtValue(const KeyAuthorization: string): string;
var
  HashBytes: TBytes;
begin
  HashBytes := THashSHA2.GetHashBytes(KeyAuthorization);
  Result := Base64UrlEncode(HashBytes);
end;

procedure TAcmeClient.ValidateAuthorizations(const Auths: TArray<TAcmeAuthorization>; PrefType: TChallengeType);
begin
  // TODO:
  //  For each auth:
  //   - Pick dns-01 or http-01 challenge based on PrefType,
  //     falling back if that type not present
  //   - Find IAcmeChallengeSolver that CanSolve(challenge.type)
  //   - Compute keyAuthorization
  //   - solver.Solve(...)
  //   - POST {} to challenge.url (JwsPost)
  //   - Poll authorization URL until status=valid or timeout
  //   - solver.Cleanup(...)
end;

procedure TAcmeClient.RegisterOrLoadAccount(const Email, AccountFile: string);
begin
  // TODO:
  //  - If AccountFile exists, load FAccountKey + account URL (kid)
  //  - Else:
  //     > generate new key pair
  //     > POST newAccount with contact ["mailto:..."] and termsOfServiceAgreed
  //     > store account URL and key to AccountFile
end;

procedure TAcmeClient.ObtainCertificate(const Domains: TArray<string>;
  const Email: string; out CertificatePem, PrivateKeyPem, ChainPem: string;
  PrefType: TChallengeType; UseStaging: Boolean);
begin
  // TODO (high-level outline):
  // 1. RegisterOrLoadAccount(...)
  // 2. Create "newOrder" payload with identifiers (dns names)
  // 3. JwsPost(FDirectory.NewOrderUrl, payload) → orderObj
  // 4. GetAuthorizationsForOrder(orderObj) → auths[]
  // 5. ValidateAuthorizations(auths, PrefType)
  // 6. Generate keypair for certificate; build CSR with Domains[]
  // 7. POST CSR to "finalize" URL
  // 8. Poll order URL until status=valid, then download certificate URL
  // 9. Split PEM into CertificatePem, ChainPem; PrivateKeyPem from (6)
end;

end.

