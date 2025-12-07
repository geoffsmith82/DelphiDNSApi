unit ACME.TaurusCrypto;

interface

uses
  System.SysUtils,
  System.Classes,
  System.JSON,
  System.Hash,
  System.NetEncoding;

type
  EAcmeCryptoError = class(Exception);

  TAcmeKeyType = (akRsa2048, akEcP256);

  // Wraps an OpenSSL key (EVP_PKEY *)
  TAcmeKeyPair = class
  private
    FKey: Pointer; // EVP_PKEY*
    FKeyType: TAcmeKeyType;
    procedure CheckKey;
  public
    constructor Create(AKey: Pointer; AKeyType: TAcmeKeyType);
    destructor Destroy; override;

    class function GenerateRsa2048: TAcmeKeyPair;
    class function GenerateEcP256: TAcmeKeyPair;

    function ExportPrivateKeyPem: string;
    function ExportPublicKeyPem: string;

    function BuildJwk: TJSONObject;
    function ComputeJwkThumbprint: string;

    // RS256 / ES256 JWS signature (result is base64url of signature)
    function SignJws(const ProtectedB64, PayloadB64: string): string;

    // CSR with SANs (DNS:domain1, DNS:domain2, ...)
    function GenerateCsrPem(const Domains: TArray<string>): string;

    property KeyType: TAcmeKeyType read FKeyType;
    property RawKey: Pointer read FKey; // EVP_PKEY*
  end;

function Base64UrlEncode(const Bytes: TBytes): string;
function Base64UrlEncodeStr(const S: string): string;

implementation

// === Shared helpers ===

function Base64UrlEncode(const Bytes: TBytes): string;
begin
  Result := TNetEncoding.Base64.EncodeBytesToString(Bytes);
  Result := Result.Replace('+', '-').Replace('/', '_').Replace('=', '');
end;

function Base64UrlEncodeStr(const S: string): string;
begin
  Result := Base64UrlEncode(TEncoding.UTF8.GetBytes(S));
end;

// === TAcmeKeyPair ===

constructor TAcmeKeyPair.Create(AKey: Pointer; AKeyType: TAcmeKeyType);
begin
  inherited Create;
  FKey := AKey;
  FKeyType := AKeyType;
end;

destructor TAcmeKeyPair.Destroy;
begin
  if FKey <> nil then
  begin
    // TODO: call EVP_PKEY_free(FKey) via TaurusTLSHeaders_* unit
    // EVP_PKEY_free(FKey);
    FKey := nil;
  end;
  inherited;
end;

procedure TAcmeKeyPair.CheckKey;
begin
  if FKey = nil then
    raise EAcmeCryptoError.Create('Key not initialised');
end;

class function TAcmeKeyPair.GenerateRsa2048: TAcmeKeyPair;
var
  Key: Pointer; // EVP_PKEY*
begin
  // TODO:
  //   - Use TaurusTLSHeaders_* wrappers for:
  //       ctx := EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nil);
  //       EVP_PKEY_keygen_init(ctx);
  //       EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
  //       EVP_PKEY_keygen(ctx, @Key);
  //   - Free ctx with EVP_PKEY_CTX_free
  Key := nil;
  raise EAcmeCryptoError.Create('GenerateRsa2048 not wired to OpenSSL yet');

  Result := TAcmeKeyPair.Create(Key, akRsa2048);
end;

class function TAcmeKeyPair.GenerateEcP256: TAcmeKeyPair;
var
  Key: Pointer; // EVP_PKEY*
begin
  // TODO:
  //   - Use EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nil)
  //   - Set curve NID_X9_62_prime256v1
  //   - EVP_PKEY_keygen(...)
  Key := nil;
  raise EAcmeCryptoError.Create('GenerateEcP256 not wired to OpenSSL yet');

  Result := TAcmeKeyPair.Create(Key, akEcP256);
end;

function TAcmeKeyPair.ExportPrivateKeyPem: string;
begin
  CheckKey;
  // TODO:
  //   - BIO_new(BIO_s_mem)
  //   - PEM_write_bio_PrivateKey(bio, FKey, nil, nil, 0, nil, nil);
  //   - BIO_read into Result (UTF-8 string)
  raise EAcmeCryptoError.Create('ExportPrivateKeyPem not implemented');
end;

function TAcmeKeyPair.ExportPublicKeyPem: string;
begin
  CheckKey;
  // TODO:
  //   - BIO_new
  //   - PEM_write_bio_PUBKEY(bio, FKey)
  raise EAcmeCryptoError.Create('ExportPublicKeyPem not implemented');
end;

function TAcmeKeyPair.BuildJwk: TJSONObject;
var
  NStr, EStr, XStr, YStr: string;
begin
  CheckKey;
  Result := TJSONObject.Create;

  case FKeyType of
    akRsa2048:
    begin
      // TODO:
      //   - Use EVP_PKEY_get_bn_param(EVP_PKEY_RSA, 'n'/ 'e', ...)
      //   - Convert BIGNUM to bytes and Base64Url encode
      NStr := 'TODO_n';
      EStr := 'TODO_e';

      Result.AddPair('kty', 'RSA');
      Result.AddPair('n', NStr);
      Result.AddPair('e', EStr);
    end;
    akEcP256:
    begin
      // TODO:
      //   - Use EVP_PKEY_get_bn_param for 'x'/'y'
      XStr := 'TODO_x';
      YStr := 'TODO_y';

      Result.AddPair('kty', 'EC');
      Result.AddPair('crv', 'P-256');
      Result.AddPair('x', XStr);
      Result.AddPair('y', YStr);
    end;
  end;
end;

function TAcmeKeyPair.ComputeJwkThumbprint: string;
var
  Jwk: TJSONObject;
  Canon: string;
  HashBytes: TBytes;
begin
  Jwk := BuildJwk;
  try
    // Canonical JSON per RFC 7638:
    // For RSA: {"e":"...","kty":"RSA","n":"..."}
    // For EC:  {"crv":"P-256","kty":"EC","x":"...","y":"..."}
    case FKeyType of
      akRsa2048:
        Canon := Format('{"e":"%s","kty":"RSA","n":"%s"}',
                        [Jwk.GetValue('e').Value, Jwk.GetValue('n').Value]);
      akEcP256:
        Canon := Format('{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}',
                        [Jwk.GetValue('x').Value, Jwk.GetValue('y').Value]);
    end;

    HashBytes := THashSHA2.GetHashBytes(Canon);
    Result := Base64UrlEncode(HashBytes);
  finally
    Jwk.Free;
  end;
end;

function TAcmeKeyPair.SignJws(const ProtectedB64, PayloadB64: string): string;
var
  ToSign: string;
  SigBytes: TBytes;
begin
  CheckKey;
  ToSign := ProtectedB64 + '.' + PayloadB64;

  // TODO:
  //   - Use EVP_DigestSignInit / EVP_DigestSign with SHA-256 and FKey
  //   - For RSA: RSASSA-PKCS1-v1_5 w/ SHA-256 (alg "RS256")
  //   - For EC: ECDSA with SHA-256 (alg "ES256")
  //   - Put raw signature into SigBytes

  raise EAcmeCryptoError.Create('SignJws not implemented');

  Result := Base64UrlEncode(SigBytes);
end;

function TAcmeKeyPair.GenerateCsrPem(const Domains: TArray<string>): string;
var
  // req: PX509_REQ;
  // name: PX509_NAME;
  i: Integer;
begin
  CheckKey;
  // TODO:
  //   - req := X509_REQ_new();
  //   - X509_REQ_set_pubkey(req, FKey);
  //   - subject CN = first domain
  //   - Build SAN extension with DNS:domain1, DNS:domain2,...
  //   - X509_REQ_sign(req, FKey, EVP_sha256());
  //   - PEM_write_bio_X509_REQ to memory BIO → Result
  for i := Low(Domains) to High(Domains) do
    if Domains[i] = '' then
      raise EAcmeCryptoError.Create('Empty domain not allowed');

  raise EAcmeCryptoError.Create('GenerateCsrPem not implemented');
end;

end.

