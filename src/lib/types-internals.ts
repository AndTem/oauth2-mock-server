import { JWK as JoseJWK } from 'jose/types';

export interface JWKWithKid extends JoseJWK {
  kid: string;
}

export enum InternalEvents {
  BeforeSigning = 'beforeSigning',
}
