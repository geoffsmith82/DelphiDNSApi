unit ACME.Client;

interface

uses
  System.SysUtils,
  System.Classes,
  System.StrUtils,
  System.Generics.Collections,
  System.Net.HttpClient,
  System.Net.URLClient,
  System.JSON,
  ACME.Client.Types,
  ACME.TaurusCrypto;

type
  EAcmeClientError = class(Exception);

  TAcmeClient = class
  private
    FHttp        : THTTPClient;
    FDirectoryUrl: string;
    FDirectory   : TAcmeDirectory;
    FSolvers     : TList<IAcmeChallengeSolver>;

    FAccountKey  : TAcmeKeyPair;
    FAccountUrl  : string;  // account URL (kid)
    FAccountFile : string;

    procedure LoadDirectory;
    function NewNonce: string;

    function RawPost(const Url, JwsBody: string; out Location: string): TJSONObject;
    function JwsPost(const Url: string; Payload: TJSONValue;
      UseKid: Boolean; out Location: string): TJSONObject;

    function StatusFromStr(const S: string): TAcmeAuthorizationStatus;
    function GetAuthorizationsForOrder(const OrderObj: TJSONObject): TArray<TAcmeAuthorization>;
    function GetChallengeForAuth(const Auth: TAcmeAuthorization;
      PrefType: TChallengeType; out Chall: TAcmeChallenge): Boolean;

    function ComputeKeyAuthorization(const Token: string): string;
    procedure ValidateAuthorizations(const OrderObj: TJSONObject;
      PrefType: TChallengeType; const OrderUrl: string);

    function DownloadCertPem(const CertUrl: string): string;
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
  System.Math,
  System.IOUtils;

{ TAcmeClient *****************************************************************}

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
  FreeAndNil(FAccountKey);
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
  Obj: TJSONObject;
begin
  Resp := FHttp.Get(FDirectoryUrl);
  if (Resp.StatusCode div 100) <> 2 then
    raise EAcmeClientError.CreateFmt('Directory GET failed: %d %s',
      [Resp.StatusCode, Resp.StatusText]);

  Obj := TJSONObject.ParseJSONValue(Resp.ContentAsString) as TJSONObject;
  try
    FDirectory.NewNonceUrl   := Obj.GetValue<string>('newNonce');
    FDirectory.NewAccountUrl := Obj.GetValue<string>('newAccount');
    FDirectory.NewOrderUrl   := Obj.GetValue<string>('newOrder');
  finally
    FreeAndNil(Obj);
  end;
end;

function TAcmeClient.NewNonce: string;
var
  Resp: IHTTPResponse;
begin
  Resp := FHttp.Head(FDirectory.NewNonceUrl);
  if (Resp.StatusCode div 100) <> 2 then
    raise EAcmeClientError.CreateFmt('newNonce failed: %d %s',
      [Resp.StatusCode, Resp.StatusText]);
  Result := Resp.HeaderValue['Replay-Nonce'];
end;

function TAcmeClient.RawPost(const Url, JwsBody: string; out Location: string): TJSONObject;
var
  Resp: IHTTPResponse;
  Content: TStringStream;
  Headers: TNetHeaders;
begin
  Location := '';

  SetLength(Headers, 1);
  Headers[0].Name  := 'Content-Type';
  Headers[0].Value := 'application/jose+json';

  Content := TStringStream.Create(JwsBody, TEncoding.UTF8);
  try
    Resp := FHttp.Post(Url, Content, nil, Headers);
  finally
    FreeAndNil(Content);
  end;

  if Resp = nil then
    raise EAcmeClientError.Create('HTTP POST returned nil response');

  Location := Resp.HeaderValue['Location'];

  if (Resp.StatusCode < 200) or (Resp.StatusCode >= 300) then
    raise EAcmeClientError.CreateFmt(
      'POST %s failed: %d %s%s%s',
      [Url, Resp.StatusCode, Resp.StatusText, sLineBreak, Resp.ContentAsString]
    );

  if Resp.ContentLength = 0 then
    Exit(nil);

  Result := TJSONObject.ParseJSONValue(Resp.ContentAsString) as TJSONObject;
end;


function TAcmeClient.JwsPost(const Url: string; Payload: TJSONValue;
  UseKid: Boolean; out Location: string): TJSONObject;
var
  Nonce: string;
  HeaderObj: TJSONObject;
  ProtectedHdr, ProtectedB64: string;
  PayloadStr, PayloadB64: string;
  SignatureB64: string;
  BodyObj: TJSONObject;
begin
  Nonce := NewNonce;

  HeaderObj := TJSONObject.Create;
  try
    if FAccountKey = nil then
      raise EAcmeClientError.Create('Account key not initialised (TAcmeKeyPair.GenerateRsa2048 must be implemented)');

    if FAccountKey.KeyType = akRsa2048 then
      HeaderObj.AddPair('alg', 'RS256')
    else
      HeaderObj.AddPair('alg', 'ES256');

    HeaderObj.AddPair('nonce', Nonce);
    HeaderObj.AddPair('url', Url);

    if UseKid then
    begin
      if FAccountUrl = '' then
        raise EAcmeClientError.Create('Account Url is empty – RegisterOrLoadAccount must complete successfully');
      HeaderObj.AddPair('kid', FAccountUrl);
    end
    else
    begin
      // JWK-based header for newAccount
      HeaderObj.AddPair('jwk', FAccountKey.BuildJwk); // BuildJwk must be implemented in TaurusTLS layer
    end;

    ProtectedHdr := HeaderObj.ToJSON;
  finally
    FreeAndNil(HeaderObj);
  end;

  ProtectedB64 := Base64UrlEncodeStr(ProtectedHdr);

  if Assigned(Payload) then
    PayloadStr := Payload.ToJSON
  else
    PayloadStr := '{}'; // POST-as-GET

  PayloadB64 := Base64UrlEncodeStr(PayloadStr);

  SignatureB64 := FAccountKey.SignJws(ProtectedB64, PayloadB64);

  BodyObj := TJSONObject.Create;
  try
    BodyObj.AddPair('protected', ProtectedB64);
    BodyObj.AddPair('payload', PayloadB64);
    BodyObj.AddPair('signature', SignatureB64);

    Result := RawPost(Url, BodyObj.ToJSON, Location);
  finally
    FreeAndNil(BodyObj);
  end;
end;

function TAcmeClient.StatusFromStr(const S: string): TAcmeAuthorizationStatus;
begin
  if SameText(S, 'valid') then
    Result := asValid
  else if SameText(S, 'pending') then
    Result := asPending
  else
    Result := asInvalid;
end;

function TAcmeClient.GetAuthorizationsForOrder(
  const OrderObj: TJSONObject): TArray<TAcmeAuthorization>;
var
  AuthUrls: TJSONArray;
  Auths: TList<TAcmeAuthorization>;
  I: Integer;
  Url: string;
  Resp: IHTTPResponse;
  AuthObj, IdentObj: TJSONObject;
  ChallArr: TJSONArray;
  J: Integer;
  A: TAcmeAuthorization;
  C: TAcmeChallenge;
  ChallObj: TJSONObject;
begin
  AuthUrls := OrderObj.GetValue('authorizations') as TJSONArray;
  if AuthUrls = nil then
    Exit(nil);

  Auths := TList<TAcmeAuthorization>.Create;
  try
    for I := 0 to AuthUrls.Count - 1 do
    begin
      Url := AuthUrls.Items[I].Value;
      Resp := FHttp.Get(Url);
      if (Resp.StatusCode div 100) <> 2 then
        raise EAcmeClientError.CreateFmt('Get auth failed: %d %s',
          [Resp.StatusCode, Resp.StatusText]);

      AuthObj := TJSONObject.ParseJSONValue(Resp.ContentAsString) as TJSONObject;
      try
        IdentObj := AuthObj.GetValue('identifier') as TJSONObject;
        A.Identifier := IdentObj.GetValue<string>('value');
        A.Status := StatusFromStr(AuthObj.GetValue<string>('status'));

        ChallArr := AuthObj.GetValue('challenges') as TJSONArray;
        SetLength(A.Challenges, ChallArr.Count);
        for J := 0 to ChallArr.Count - 1 do
        begin
          ChallObj := ChallArr.Items[J] as TJSONObject;
          C.ChallengeType := ChallObj.GetValue<string>('type');
          C.Url           := ChallObj.GetValue<string>('url');
          C.Token         := ChallObj.GetValue<string>('token');
          A.Challenges[J] := C;
        end;

        Auths.Add(A);
      finally
        AuthObj.Free;
      end;
    end;

    Result := Auths.ToArray;
  finally
    FreeAndNil(Auths);
  end;
end;

function TAcmeClient.GetChallengeForAuth(const Auth: TAcmeAuthorization;
  PrefType: TChallengeType; out Chall: TAcmeChallenge): Boolean;
var
  I: Integer;
  Wanted: string;
begin
  case PrefType of
    ctDns01:  Wanted := 'dns-01';
    ctHttp01: Wanted := 'http-01';
  else
    Wanted := '';
  end;

  // First try preferred type
  for I := 0 to Length(Auth.Challenges) - 1 do
    if SameText(Auth.Challenges[I].ChallengeType, Wanted) then
    begin
      Chall := Auth.Challenges[I];
      Exit(True);
    end;

  // Fallback to first available challenge
  if Length(Auth.Challenges) > 0 then
  begin
    Chall := Auth.Challenges[0];
    Exit(True);
  end;

  Result := False;
end;

function TAcmeClient.ComputeKeyAuthorization(const Token: string): string;
begin
  if FAccountKey = nil then
    raise EAcmeClientError.Create('Account key not initialised');
  Result := Token + '.' + FAccountKey.ComputeJwkThumbprint;
end;

procedure TAcmeClient.ValidateAuthorizations(const OrderObj: TJSONObject;
  PrefType: TChallengeType; const OrderUrl: string);
var
  Auths: TArray<TAcmeAuthorization>;
  Auth: TAcmeAuthorization;
  Chall: TAcmeChallenge;
  Solver: IAcmeChallengeSolver;
  KeyAuth: string;
  dummy: string;
  Payload: TJSONObject;
  Resp: TJSONObject;
  AllValid: Boolean;
  Attempt: Integer;
begin
  // 1. Present challenges
  Auths := GetAuthorizationsForOrder(OrderObj);

  for Auth in Auths do
  begin
    if not GetChallengeForAuth(Auth, PrefType, Chall) then
      raise EAcmeClientError.CreateFmt('No suitable challenge for %s', [Auth.Identifier]);

    Solver := nil;
    for Solver in FSolvers do
      if Solver.CanSolve(Chall.ChallengeType) then
        Break;

    if (Solver = nil) or (not Solver.CanSolve(Chall.ChallengeType)) then
      raise EAcmeClientError.CreateFmt('No solver for challenge type %s', [Chall.ChallengeType]);

    KeyAuth := ComputeKeyAuthorization(Chall.Token);
    Solver.Solve(Auth.Identifier, Chall, KeyAuth);

    // Notify ACME that challenge is ready (empty JSON)
    Payload := TJSONObject.Create;
    try
      Resp := JwsPost(Chall.Url, Payload, True, dummy); // Location ignored here
    finally
      FreeAndNil(Payload);
      FreeAndNil(Resp);
    end;
  end;

  // 2. Poll authorizations until all are valid or timeout
  for Attempt := 1 to 30 do
  begin
    Sleep(2000);
    Auths := GetAuthorizationsForOrder(OrderObj);
    AllValid := True;
    for Auth in Auths do
      if Auth.Status <> asValid then
      begin
        AllValid := False;
        Break;
      end;
    if AllValid then
      Break;
  end;

  if not AllValid then
    raise EAcmeClientError.Create('Authorization validation timeout');

  // 3. Cleanup local resources (DNS/HTTP)
  for Auth in Auths do
    if GetChallengeForAuth(Auth, PrefType, Chall) then
      for Solver in FSolvers do
        if Solver.CanSolve(Chall.ChallengeType) then
          Solver.Cleanup(Auth.Identifier, Chall);
end;

procedure TAcmeClient.RegisterOrLoadAccount(const Email: string; const AccountFile: string);
var
  Json: TJSONObject;
  S: TStringList;
  KeyPem: string;
  AccountUrl: string;
  Payload: TJSONObject;
  Resp: TJSONObject;
  Location: string;
begin
  // ==============================================================
  // 1. Load existing account if file exists
  // ==============================================================

  if FileExists(AccountFile) then
  begin
    S := TStringList.Create;
    try
      S.LoadFromFile(AccountFile);
      Json := TJSONObject.ParseJSONValue(S.Text) as TJSONObject;
      if Json = nil then
        raise EAcmeClientError.Create('Invalid account file JSON');

      try
        AccountUrl := Json.GetValue<string>('AccountUrl');
        KeyPem     := Json.GetValue<string>('PrivateKeyPem');
      finally
        Json.Free;
      end;
    finally
      S.Free;
    end;

    // Restore RSA key from PEM
    FAccountKey := TAcmeKeyPair.LoadKeyFromPem(KeyPem);
    FAccountUrl := AccountUrl;

    Exit; // fully loaded; ready for ACME use
  end;

  // ==============================================================
  // 2. No existing account → Register new one
  // ==============================================================

  // Generate RSA-2048 account key
  FAccountKey := TAcmeKeyPair.GenerateRsa2048;

  // Prepare ACME newAccount payload
  Payload := TJSONObject.Create;
  try
    Payload.AddPair('termsOfServiceAgreed', TJSONBool.Create(True));
    if Email <> '' then
      Payload.AddPair('contact',
        TJSONArray.Create(TJSONString.Create('mailto:' + Email)));

    Resp := JwsPost(FDirectory.NewAccountUrl, Payload, {UseKid=} False, Location);
  finally
    Payload.Free;
  end;

  try
    // ACME returns the account URL (kid) in Location header
    if Location = '' then
      raise EAcmeClientError.Create('newAccount: missing Location header');

    FAccountUrl := Location;
  finally
    Resp.Free;
  end;

  // ==============================================================
  // 3. Save account to disk
  // ==============================================================

  Json := TJSONObject.Create;
  try
    KeyPem := FAccountKey.ExportPrivateKeyPem;

    Json.AddPair('AccountUrl', FAccountUrl);
    Json.AddPair('PrivateKeyPem', KeyPem);

    S := TStringList.Create;
    try
      S.Text := Json.ToJSON;
      S.SaveToFile(AccountFile, TEncoding.UTF8);
    finally
      S.Free;
    end;
  finally
    Json.Free;
  end;
end;



function TAcmeClient.DownloadCertPem(const CertUrl: string): string;
var
  Resp: IHTTPResponse;
begin
  Resp := FHttp.Get(CertUrl);
  if (Resp.StatusCode div 100) <> 2 then
    raise EAcmeClientError.CreateFmt('Certificate download failed: %d %s',
      [Resp.StatusCode, Resp.StatusText]);
  Result := Resp.ContentAsString(TEncoding.ASCII);
end;

procedure TAcmeClient.ObtainCertificate(const Domains: TArray<string>;
  const Email: string; out CertificatePem, PrivateKeyPem, ChainPem: string;
  PrefType: TChallengeType; UseStaging: Boolean);
var
  Payload: TJSONObject;
  IdArr: TJSONArray;
  IdentObj: TJSONObject;
  I: Integer;
  Resp, OrderObj: TJSONObject;
  OrderUrl, FinalizeUrl: string;
  Location: string;
  Attempts: Integer;
  Status: string;
  CertUrl: string;
  CsrDer: TBytes;
  CsrB64: string;

  function SplitChain(const AllPem: string; out Leaf, Chain: string): Boolean;
  var
    StartPos, EndPos: Integer;
    Blocks: TArray<string>;
    Tmp: string;
    P, Q: Integer;
  begin
    Result := False;
    Leaf := '';
    Chain := '';

    Tmp := AllPem;
    SetLength(Blocks, 0);

    P := Pos('-----BEGIN CERTIFICATE-----', Tmp);
    while P > 0 do
    begin
      Q := Pos('-----END CERTIFICATE-----', Tmp);
      if Q = 0 then Break;
      Q := Q + Length('-----END CERTIFICATE-----');
      Blocks := Blocks + [Copy(Tmp, P, Q - P)];
      Delete(Tmp, 1, Q);
      P := Pos('-----BEGIN CERTIFICATE-----', Tmp);
    end;

    if Length(Blocks) = 0 then
      Exit(False);

    Leaf := Blocks[0];
    if Length(Blocks) > 1 then
    begin
      Chain := '';
      for var k := 1 to High(Blocks) do
        Chain := Chain + Blocks[k] + sLineBreak;
    end
    else
      Chain := Leaf;

    Result := True;
  end;

var
  AccountFile: string;
begin
  if Length(Domains) = 0 then
    raise EAcmeClientError.Create('No domains specified for certificate request');

  // Decide where to store account info (simple default path)
  AccountFile := TPath.Combine(TPath.GetHomePath, 'acme-account.json');

  RegisterOrLoadAccount(Email, AccountFile);

  // 1) newOrder
  Payload := TJSONObject.Create;
  IdArr := TJSONArray.Create;
  try
    for I := 0 to High(Domains) do
    begin
      IdentObj := TJSONObject.Create;
      IdentObj.AddPair('type', 'dns');
      IdentObj.AddPair('value', Domains[I]);
      IdArr.AddElement(IdentObj);
    end;
    Payload.AddPair('identifiers', IdArr);

    Resp := JwsPost(FDirectory.NewOrderUrl, Payload, True, Location);
  finally
    FreeAndNil(Payload);
  end;

  OrderObj := Resp;
  try
    OrderUrl := Location;
    if OrderUrl = '' then
      // Some servers also include "location" or "url" in payload; try to read it
      if OrderObj.TryGetValue<string>('location', OrderUrl) then
      else if OrderObj.TryGetValue<string>('url', OrderUrl) then
        // ok
      else
        raise EAcmeClientError.Create('Order URL not found (Location header or url field)');

    FinalizeUrl := OrderObj.GetValue<string>('finalize');

    // 2) Solve authorizations
    ValidateAuthorizations(OrderObj, PrefType, OrderUrl);

    // 3) Generate CSR, finalize order
    CsrDer := FAccountKey.GenerateCsrDer(Domains);  // will raise until wired
    CsrB64 := Base64UrlEncode(CsrDer);

    Payload := TJSONObject.Create;
    try
      Payload.AddPair('csr', CsrB64);
      Resp := JwsPost(FinalizeUrl, Payload, True, Location);
    finally
      FreeAndNil(Payload);
      FreeAndNil(Resp);
    end;

    // 4) Poll order until valid and certificate URL present
    CertUrl := '';
    for Attempts := 1 to 30 do
    begin
      Sleep(2000);
      Resp := JwsPost(OrderUrl, nil, True, Location);
      try
        Status := Resp.GetValue<string>('status');
        if SameText(Status, 'valid') then
        begin
          CertUrl := Resp.GetValue<string>('certificate');
          Break;
        end;
      finally
        FreeAndNil(Resp);
      end;
    end;

    if CertUrl = '' then
      raise EAcmeClientError.Create('Order did not become valid or certificate URL not present');

    // 5) Download certificate chain
    CertificatePem := DownloadCertPem(CertUrl);

    if not SplitChain(CertificatePem, CertificatePem, ChainPem) then
    begin
      // fallback – no splitting possible
      ChainPem := CertificatePem;
    end;

    PrivateKeyPem := FAccountKey.ExportPrivateKeyPem;
  finally
    FreeAndNil(OrderObj);
  end;
end;

end.

