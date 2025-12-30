unit DNS.DKIM.Types;

interface

type
  TDkimKeyType = (
    dktRsa,
    dktEd25519,
    dktUnknown
  );

  TDkimParsed = record
    Version: string;        // DKIM1
    KeyType: TDkimKeyType;  // k=
    PublicKey: string;     // p=
    Flags: TArray<string>; // t=
    Hashes: TArray<string>; // h=
    Notes: string;         // n=
  end;

implementation

end.

