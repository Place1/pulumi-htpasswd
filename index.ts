import * as pulumi from '@pulumi/pulumi';
import { CreateResult, DiffResult, UpdateResult } from '@pulumi/pulumi/dynamic';
import { isEqual } from 'lodash';

export enum HtpasswdAlgorithm {
  /**
   * Use bcrypt encryption for passwords. This is currently considered to be very secure.
   */
  Bcrypt = 'Bcrypt',
}

export interface HtpasswdEntry {
  /**
   * The username for the generated htpasswd
   */
  username: string;
  /**
   * The password for the generated htpasswd
   *
   * defaults to a cryptographically random string
   * containing the following character set: [a-zA-Z-_]
   */
  password?: pulumi.Input<string>;
}

export interface HtpasswdInputs {
  /**
   * A list of username/password entries for
   * the generated htpasswd file
   */
  entries: HtpasswdEntry[];
  /**
   * The password hashing algorithm to be used
   *
   * defaults to Bcrypt
   */
  algorithm?: HtpasswdAlgorithm;
}

interface HtpasswdProviderState {
  algorithm: HtpasswdAlgorithm,
  hashedEntries: {
    entry: HtpasswdEntry,
    password: string;
    hash: string,
  }[];
}

interface HtpasswdProviderOutputs {
  // public outputs for this dynamic resource
  result: string,
  plaintextEntries: HtpasswdEntry[];

  // private outputs for use during future diffs
  state: HtpasswdProviderState,
}

class HtpasswdProvider implements pulumi.dynamic.ResourceProvider {
  private static defaultAlgorithm = HtpasswdAlgorithm.Bcrypt;

  async create(inputs: pulumi.Unwrap<HtpasswdInputs>): Promise<CreateResult> {
    const state = await this.computeState(undefined, inputs);
    const outputs = this.computeOutputs(state);
    return {
      id: randomString(),
      outs: outputs,
    };
  }

  async diff(id: string, olds: pulumi.Unwrap<HtpasswdProviderOutputs>, news: pulumi.Unwrap<HtpasswdInputs>): Promise<DiffResult> {
    if (!olds || !olds.state) {
      return { changes: true };
    }
    return {
      changes: !isEqual(olds.state.algorithm, news.algorithm ?? HtpasswdProvider.defaultAlgorithm)
        || !isEqual(
          olds.state.hashedEntries.map((s) => s.entry),
          news.entries,
        ),
    };
  }

  async update(id: string, olds: pulumi.Unwrap<HtpasswdProviderOutputs>, news: pulumi.Unwrap<HtpasswdInputs>): Promise<UpdateResult> {
    const nextState = await this.computeState(olds.state, news);
    const outputs = this.computeOutputs(nextState);
    return {
      outs: outputs,
    };
  }

  private async computeState(state: HtpasswdProviderState | undefined, inputs: pulumi.Unwrap<HtpasswdInputs>): Promise<HtpasswdProviderState> {
    // default algorithm
    const algorithm = inputs.algorithm ?? HtpasswdProvider.defaultAlgorithm;

    // default to empty state if needed
    state = state ?? {
      algorithm: algorithm,
      hashedEntries: [],
    };

    // compute entries
    const entries = await Promise.all(inputs.entries
      .map(async (entry) => {
        // if the entry already has a hash we should reuse it
        const existingEntry = state!.hashedEntries.find((s) => isEqual(s.entry, entry));
        if (existingEntry) {
          return existingEntry;
        }

        // otherwise it's a new or changed entry and we should
        // compute a new hash.
        const password = entry.password ?? randomString();
        return {
          entry: entry,
          password: password,
          hash: await createHash(entry.username, password, algorithm),
        };
      }));

    return {
      algorithm: algorithm,
      hashedEntries: entries,
    };
  }

  private computeOutputs(state: HtpasswdProviderState): HtpasswdProviderOutputs {
    // the resulting htpasswd file content
    // which is a \n concatenation of every hash
    const result = state.hashedEntries.map((e) => e.hash).join('\n');

    // the resulting entries after random
    // passwords are generated and assigned
    const plaintextEntries = state.hashedEntries.map((e) => ({
      username: e.entry.username,
      password: e.password,
    }));

    return {
      // TODO: mark these as secrets once the following bug is fixed
      // https://github.com/pulumi/pulumi/issues/3012
      // public outputs for this dynamic resource
      result: result,
      plaintextEntries: plaintextEntries,

      // private outputs for use during future diffs
      state: state,
    };
  }
}

export class Htpasswd extends pulumi.dynamic.Resource {

  readonly result!: pulumi.Output<string>;
  readonly plaintextEntries!: pulumi.Output<HtpasswdEntry[]>;

  constructor(name: string, props: HtpasswdInputs, opts?: pulumi.CustomResourceOptions) {
    super(new HtpasswdProvider(), name, {
      ...props,
      result: undefined,
      plaintextEntries: undefined,
    }, opts);
  }
}

async function createHash(username: string, password: string, algorithm: HtpasswdAlgorithm): Promise<string> {
  if (!password) {
    throw new Error(`htpasswd entry for '${username}' requires a password`);
  }

  let hash = '';
  switch (algorithm) {
    case HtpasswdAlgorithm.Bcrypt:
      // we have to do an inline require here because a top
      // level causes pulumi to crash
      // https://github.com/pulumi/pulumi/issues/5130
      hash = await require('bcryptjs').hash(password, 10);
      break;
    default:
      throw new Error('unknown HtpasswdAlgorithm');
  }

  return `${username}:${hash}`;
}

function randomString() {
  // we have to do an inline require here because a top
  // level causes pulumi to crash
  // https://github.com/pulumi/pulumi/issues/5130
  return require('crypto').randomBytes(32).toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/\=/g, '');
}
