// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
import { describe, expect, it } from 'vitest';
import { CanonicalJsonError, canonicalize, hashJson } from '../../../../src/core/crypto/jcs.js';
import * as cryptoIndex from '../../../../src/core/crypto/index.js';

/** A one-code-unit string, written by code so the source holds no escape a tool might rewrite. */
const ch = (code: number): string => String.fromCharCode(code);
const BACKSLASH = ch(0x5c);
const esc = (hex: string): string => `${BACKSLASH}u${hex}`;

describe('canonicalize (RFC 8785)', () => {
  it('is exported from the crypto index', () => {
    expect(cryptoIndex.canonicalize).toBe(canonicalize);
    expect(cryptoIndex.hashJson).toBe(hashJson);
    expect(cryptoIndex.CanonicalJsonError).toBe(CanonicalJsonError);
  });

  it('writes scalars as JSON', () => {
    expect(canonicalize(null)).toBe('null');
    expect(canonicalize(true)).toBe('true');
    expect(canonicalize(false)).toBe('false');
    expect(canonicalize('text')).toBe('"text"');
    expect(canonicalize(42)).toBe('42');
    expect(canonicalize([])).toBe('[]');
    expect(canonicalize({})).toBe('{}');
  });

  it('sorts object members and keeps array order, at every depth', () => {
    expect(canonicalize({ zeta: 1, alpha: 2, mid: 3 })).toBe('{"alpha":2,"mid":3,"zeta":1}');
    expect(canonicalize({ outer: { z: [{ b: 2, a: 1 }], a: { d: null, c: [3, 1, 2] } }, '': 0 })).toBe(
      '{"":0,"outer":{"a":{"c":[3,1,2],"d":null},"z":[{"a":1,"b":2}]}}',
    );
    expect(canonicalize({ '10': 1, '9': 2, Alpha: 3, _u: 4, alpha: 5 })).toBe('{"10":1,"9":2,"Alpha":3,"_u":4,"alpha":5}');
  });

  it('sorts member names by UTF-16 code units (RFC 8785 section 3.2.3 example)', () => {
    const value: Record<string, string> = {
      '€': 'Euro Sign',
      [ch(0x0d)]: 'Carriage Return',
      [ch(0xfb33)]: 'Hebrew Letter Dalet With Dagesh',
      '1': 'One',
      '😀': 'Emoji: Grinning Face',
      [ch(0x80)]: 'Control',
      'ö': 'Latin Small Letter O With Diaeresis',
    };
    const order = [ch(0x0d), '1', ch(0x80), 'ö', '€', '😀', ch(0xfb33)];
    const members = order.map((key) => `${JSON.stringify(key)}:${JSON.stringify(value[key])}`);
    expect(canonicalize(value)).toBe(`{${members.join(',')}}`);
  });

  it('writes numbers per RFC 8785 section 3.2.2.3 (ECMAScript Number::toString)', () => {
    // eslint-disable-next-line no-loss-of-precision -- the RFC's literal, read as the nearest double
    expect(canonicalize([-0, 1e-7, 1e21 / 1e6, 0.1 + 0.2, 333333333.33333329, 5e-324, 100, 0.000001, 1e-5])).toBe(
      '[0,1e-7,1000000000000000,0.30000000000000004,333333333.3333333,5e-324,100,0.000001,0.00001]',
    );
    expect(canonicalize([9007199254740991, -9007199254740991, 2.220446049250313e-16, -2.5, 4.5, 2e-3, 1e-27])).toBe(
      '[9007199254740991,-9007199254740991,2.220446049250313e-16,-2.5,4.5,0.002,1e-27]',
    );
  });

  it('escapes strings as JSON.stringify does and writes everything else as itself', () => {
    const value = `${ch(0)}${ch(0x1f)}"${BACKSLASH}/${ch(0x7f)}${ch(0x2028)}€😀`;
    expect(canonicalize(value)).toBe(
      `"${esc('0000')}${esc('001f')}${BACKSLASH}"${BACKSLASH}${BACKSLASH}/${ch(0x7f)}${ch(0x2028)}€😀"`,
    );
    expect(canonicalize(`${ch(8)}${ch(12)}${ch(10)}${ch(13)}${ch(9)}`)).toBe(
      `"${BACKSLASH}b${BACKSLASH}f${BACKSLASH}n${BACKSLASH}r${BACKSLASH}t"`,
    );
  });

  it('matches the RFC 8785 appendix sample (minus 1E30, an integer outside the safe range)', () => {
    const sample = {
      // eslint-disable-next-line no-loss-of-precision -- the RFC's literal, read as the nearest double
      numbers: [333333333.33333329, 4.5, 2e-3, 0.000000000000000000000000001],
      string: `€$${ch(0x0f)}${ch(0x0a)}A'B"${BACKSLASH}${BACKSLASH}"/`,
      literals: [null, true, false],
    };
    expect(canonicalize(sample)).toBe(
      `{"literals":[null,true,false],"numbers":[333333333.3333333,4.5,0.002,1e-27],"string":"€$${esc('000f')}${BACKSLASH}nA'B${BACKSLASH}"${BACKSLASH}${BACKSLASH}${BACKSLASH}${BACKSLASH}${BACKSLASH}"/"}`,
    );
  });

  it('treats a toJSON member as data, accepts null-prototype objects, and reuses (not cycles) are fine', () => {
    expect(canonicalize({ toJSON: 'x', b: 1, a: 2 })).toBe('{"a":2,"b":1,"toJSON":"x"}');
    expect(canonicalize(Object.assign(Object.create(null) as object, { z: 1, a: [true, null] }))).toBe('{"a":[true,null],"z":1}');
    const leaf = { a: 1 };
    expect(canonicalize([leaf, { x: leaf }, leaf])).toBe('[{"a":1},{"x":{"a":1}},{"a":1}]');
  });

  describe('refuses a value with no single JSON form', () => {
    const refusals: [name: string, build: () => unknown, message: string][] = [
      ['NaN', () => NaN, 'Cannot canonicalize a non-finite number (NaN) at $'],
      ['Infinity', () => [Infinity], 'Cannot canonicalize a non-finite number (Infinity) at $[0]'],
      ['-Infinity', () => ({ n: -Infinity }), 'Cannot canonicalize a non-finite number (-Infinity) at $.n'],
      ['2^53', () => 2 ** 53, 'Cannot canonicalize an integer outside the safe range (9007199254740992) at $'],
      ['-2^53', () => -(2 ** 53), 'Cannot canonicalize an integer outside the safe range (-9007199254740992) at $'],
      ['1e21', () => 1e21, 'Cannot canonicalize an integer outside the safe range (1e+21) at $'],
      ['undefined', () => undefined, 'Cannot canonicalize a undefined at $'],
      ['an undefined member', () => ({ a: undefined }), 'Cannot canonicalize a undefined at $.a'],
      ['an undefined element', () => [1, [undefined]], 'Cannot canonicalize a undefined at $[1][0]'],
      ['a function', () => ({ toJSON: () => 1 }), 'Cannot canonicalize a function at $.toJSON'],
      ['a symbol', () => Symbol('s'), 'Cannot canonicalize a symbol at $'],
      ['a bigint', () => 10n, 'Cannot canonicalize a bigint at $'],
      ['a Date', () => new Date(0), 'Cannot canonicalize a non-plain object at $'],
      ['a Map', () => ({ m: new Map() }), 'Cannot canonicalize a non-plain object at $.m'],
      ['a Uint8Array', () => [new Uint8Array(1)], 'Cannot canonicalize a non-plain object at $[0]'],
      ['a class instance', () => new (class Point {})(), 'Cannot canonicalize a non-plain object at $'],
      ['a sparse array', () => Object.assign(new Array<unknown>(3), { 0: 1, 2: 3 }), 'Cannot canonicalize a sparse array element at $[1]'],
      ['a symbol-keyed member', () => ({ a: 1, [Symbol('k')]: 2 }), 'Cannot canonicalize a symbol-keyed member at $'],
      ['a lone high surrogate', () => `a${ch(0xd83d)}`, 'Cannot canonicalize a string with a lone surrogate at $'],
      ['a lone low surrogate', () => ({ s: `${ch(0xdc00)}b` }), 'Cannot canonicalize a string with a lone surrogate at $.s'],
      ['a lone surrogate in a member name', () => ({ [ch(0xd800)]: 1 }), `Cannot canonicalize a string with a lone surrogate at $.${ch(0xd800)}`],
    ];
    it.each(refusals)('%s', (_name, build, message) => {
      expect(() => canonicalize(build())).toThrow(CanonicalJsonError);
      expect(() => canonicalize(build())).toThrow(message);
      expect(() => hashJson(build())).toThrow(message);
    });

    it('refuses an object cycle and an array cycle by path', () => {
      const object: Record<string, unknown> = { a: 1 };
      object['self'] = { back: object };
      expect(() => canonicalize(object)).toThrow('Cannot canonicalize a cyclic reference at $.self.back');
      const array: unknown[] = [1];
      array.push(array);
      expect(() => canonicalize(array)).toThrow('Cannot canonicalize a cyclic reference at $[1]');
    });

    it('throws its own error class, a named TypeError', () => {
      let thrown: unknown;
      try {
        canonicalize({ a: undefined });
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toBeInstanceOf(CanonicalJsonError);
      expect(thrown).toBeInstanceOf(TypeError);
      expect((thrown as Error).name).toBe('CanonicalJsonError');
      expect((thrown as Error).message).toBe('Cannot canonicalize a undefined at $.a');
    });
  });
});

describe('hashJson (KYA-OS SPEC section 7.3)', () => {
  it('writes sha256:<64 lowercase hex> over the UTF-8 canonical bytes', () => {
    expect(hashJson({})).toBe('sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a');
    expect(hashJson({ b: '€', a: 1 })).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(hashJson({ b: '€', a: 1 })).toBe(hashJson({ a: 1, b: '€' }));
    expect(hashJson({ a: 1 })).not.toBe(hashJson({ a: 1.0000001 }));
  });

  it('matches the SPEC appendix C.1 vectors', () => {
    expect(hashJson({ method: 'tools/call', params: { name: 'echo', arguments: {} } })).toBe(
      'sha256:5057521f310b536837b619f0ac040ef8064f8c597da8ec22a56801b435744033',
    );
    expect(hashJson({ method: 'tools/call', params: { name: 'echo', arguments: { msg: 'hi' } } })).toBe(
      'sha256:c8f3d59959c9247211de8c76b94ef17f0c279f09362350ced67f69ecdb89d6c7',
    );
  });
});
