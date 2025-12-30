unit DNS.DMARC.Types;

interface

type
  TDmarcPolicy = (
    dmpNone,
    dmpQuarantine,
    dmpReject
  );

  TDmarcAlignment = (
    daRelaxed,
    daStrict
  );

  TDmarcParsed = record
    Version: string;               // DMARC1
    Policy: TDmarcPolicy;          // p=
    SubdomainPolicy: TDmarcPolicy; // sp=
    Adkim: TDmarcAlignment;        // adkim=
    Aspf: TDmarcAlignment;         // aspf=
    Pct: Integer;                  // pct=
    Rua: TArray<string>;           // rua=
    Ruf: TArray<string>;           // ruf=
    Fo: TArray<string>;            // fo=
  end;

implementation

end.

