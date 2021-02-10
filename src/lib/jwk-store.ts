/**
 * Copyright (c) AXA Assistance France
 *
 * Licensed under the AXA Assistance France License (the "License"); you
 * may not use this file except in compliance with the License.
 * A copy of the License can be found in the LICENSE.md file distributed
 * together with this file.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * JWK Store library
 *
 * @module lib/jwk-store
 */

import { KeyObject, randomBytes } from 'crypto';

import {
  generateKeyPair,
  GenerateKeyPairOptions,
} from 'jose/util/generate_key_pair';
import { fromKeyLike } from 'jose/jwk/from_key_like';
import { parseJwk } from 'jose/jwk/parse';
import type { JWK } from 'jose/types';

import { assertIsString } from './helpers';

const generateRandomKid = () => {
  return randomBytes(40).toString('hex');
};

const removeKey = (k: string, obj: Record<string, unknown>) => {
  const x = { ...obj };
  delete x[k];
  return x;
};

const removeKeys = (keys: string[], o: Record<string, unknown>) =>
  keys.reduce((r, k) => removeKey(k, r), o);

type JwkTransformer = (jwk: JWK) => JWK;

const RsaPrivateFieldsRemover: JwkTransformer = (jwk) => {
  return removeKeys(['d', 'p', 'q', 'dp', 'dq', 'qi'], jwk);
};

const EcdsaPrivateFieldsRemover: JwkTransformer = (jwk) => {
  return removeKeys(['d'], jwk);
};

const EddsaPrivateFieldsRemover: JwkTransformer = (jwk) => {
  return removeKeys(['d'], jwk);
};

const privateToPublicTransformerMap: Record<string, JwkTransformer> = {
  RS256: RsaPrivateFieldsRemover,
  RS384: RsaPrivateFieldsRemover,
  RS512: RsaPrivateFieldsRemover,

  // RSASSA-PSS
  PS256: RsaPrivateFieldsRemover,
  PS384: RsaPrivateFieldsRemover,
  PS512: RsaPrivateFieldsRemover,

  // ECDSA
  ES256: EcdsaPrivateFieldsRemover,
  ES256K: EcdsaPrivateFieldsRemover,
  ES384: EcdsaPrivateFieldsRemover,
  ES512: EcdsaPrivateFieldsRemover,

  // Edwards-curve DSA
  EdDSA: EddsaPrivateFieldsRemover,
};

const supportedAlgs = Object.keys(privateToPublicTransformerMap);

const normalizeKey = (jwk: JWK, opts?: { kid?: string }): void => {
  if (jwk.kid !== undefined) {
    return;
  }

  if (opts !== undefined && opts.kid !== undefined) {
    jwk.kid = opts.kid;
  } else {
    jwk.kid = generateRandomKid();
  }
};

/**
 * Simple JWK store
 */
export class JWKStore {
  #keyRotator: KeyRotator;

  /**
   * Creates a new instance of the keystore.
   */
  constructor() {
    this.#keyRotator = new KeyRotator();
  }

  /**
   * Generates a new random key and adds it into this keystore.
   *
   * @param {string} alg The selected algorithm.
   * @param {object} [opts] The options.
   * @param {string} [opts.kid] The key identifier to use.
   * @param {string} [opts.crv] The OKP "crv" to be used for "EdDSA" algorithm.
   * @returns {Promise<JWK>} The promise for the generated key.
   */
  async generate(
    alg: string,
    opts?: { kid?: string; crv?: string }
  ): Promise<JWK> {
    const generateOpts: GenerateKeyPairOptions =
      opts !== undefined && opts.crv !== undefined ? { crv: opts.crv } : {};

    const pair = await generateKeyPair(alg, generateOpts);
    const jwk = await fromKeyLike(pair.privateKey);

    jwk.alg = alg;
    normalizeKey(jwk, opts);

    this.#keyRotator.add(jwk);
    return jwk;
  }

  /**
   * Adds a JWK key to this keystore.
   *
   * @param {JWK} jwk The JWK key to add.
   * @returns {Promise<JWK>} The promise for the added key.
   */
  async add(jwk: JWK): Promise<JWK> {
    const jwkUse: JWK = { ...jwk };

    normalizeKey(jwkUse);

    if (jwkUse.alg === undefined) {
      throw new Error('Unspecified JWK "alg" property');
    }

    if (!supportedAlgs.includes(jwkUse.alg)) {
      throw new Error(`Unsupported JWK "alg" value ("${jwkUse.alg}")`);
    }

    const privateKey = await parseJwk(jwkUse);

    if (!(privateKey instanceof KeyObject) || privateKey.type !== 'private') {
      throw new Error(
        `Invalid JWK type. No "private" key related data has been found.`
      );
    }

    this.#keyRotator.add(jwkUse);

    return jwkUse;
  }

  /**
   * Gets a key from the keystore in a round-robin fashion.
   * If a 'kid' is provided, only keys that match will be taken into account.
   *
   * @param {string} [kid] The optional key identifier to match keys against.
   * @returns {JWK.Key | null} The retrieved key.
   */
  get(kid?: string): JWK | undefined {
    return this.#keyRotator.next(kid);
  }

  /**
   * Generates a JSON representation of this keystore, which conforms
   * to a JWK Set from {I-D.ietf-jose-json-web-key}.
   *
   * @param {boolean} [includePrivateFields = false] `true` if the private fields
   *        of stored keys are to be included.
   * @returns {JWK[]} The JSON representation of this keystore.
   */
  toJSON(includePrivateFields = false): JWK[] {
    return this.#keyRotator.toJSON(includePrivateFields);
  }
}

class KeyRotator {
  #keys: JWK[] = [];

  add(key: JWK): void {
    const pos = this.findNext(key.kid);

    if (pos > -1) {
      this.#keys.splice(pos, 1);
    }

    this.#keys.push(key);
  }

  next(kid?: string): JWK | undefined {
    const i = this.findNext(kid);

    if (i === -1) {
      return undefined;
    }

    return this.moveToTheEnd(i);
  }

  toJSON(includePrivateFields: boolean): JWK[] {
    const keys: JWK[] = [];

    for (const key of this.#keys) {
      if (includePrivateFields) {
        keys.push({ ...key });
        continue;
      }

      assertIsString(key.alg, 'Missing "alg" field');

      if (!(key.alg in privateToPublicTransformerMap)) {
        throw new Error(`Unsupported JWK "alg" value ("${key.alg}")`);
      }

      const cleaner = privateToPublicTransformerMap[key.alg];
      keys.push(cleaner(key));
    }

    return keys;
  }

  private findNext(kid?: string): number {
    if (this.#keys.length === 0) {
      return -1;
    }

    if (kid === undefined) {
      return 0;
    }

    return this.#keys.findIndex((x) => x.kid === kid);
  }

  private moveToTheEnd(i: number): JWK {
    const [key] = this.#keys.splice(i, 1);

    this.#keys.push(key);

    return key;
  }
}
