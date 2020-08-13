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

class HtpasswdProvider implements pulumi.dynamic.ResourceProvider {
  private static defaultAlgorithm = HtpasswdAlgorithm.Bcrypt;

  async create(inputs: pulumi.Unwrap<HtpasswdInputs>): Promise<CreateResult> {
    const algorithm = inputs.algorithm ?? HtpasswdProvider.defaultAlgorithm;

    const entries = inputs.entries.map((entry) => ({
      username: entry.username,
      password: entry.password ?? randomString(),
    }));

    const hashes = await Promise.all(entries.map((entry) => {
      return createHash(entry, algorithm);
    }));

    const result = hashes.join('\n');

    return {
      id: randomString(),
      outs: {
        // TODO: mark these as secrets once the following bug is fixed
        // https://github.com/pulumi/pulumi/issues/3012
        result: result,
        plaintextEntries: entries,

        // output used for future diffs
        algorithm: inputs.algorithm ?? HtpasswdProvider.defaultAlgorithm,
        entries: inputs.entries,
      },
    };
  }

  async diff(id: string, olds: pulumi.Unwrap<HtpasswdInputs>, news: pulumi.Unwrap<HtpasswdInputs>): Promise<DiffResult> {
    return {
      changes: !isEqual(olds.algorithm, news.algorithm ?? HtpasswdProvider.defaultAlgorithm)
        || !isEqual(olds.entries, news.entries),
    };
  }

  async update(id: string, olds: pulumi.Unwrap<HtpasswdInputs>, news: pulumi.Unwrap<HtpasswdInputs>): Promise<UpdateResult> {
    const { outs } = await this.create(news);
    return { outs };
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

function randomString() {
  // we have to do an inline require here because a top
  // level causes pulumi to crash
  // https://github.com/pulumi/pulumi/issues/5130
  return require('crypto').randomBytes(32).toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/\=/g, '');
}

async function createHash(entry: pulumi.Unwrap<HtpasswdEntry>, algorithm: HtpasswdAlgorithm): Promise<string> {
  let hash = '';
  switch (algorithm) {
    case HtpasswdAlgorithm.Bcrypt:
      // we have to do an inline require here because a top
      // level causes pulumi to crash
      // https://github.com/pulumi/pulumi/issues/5130
      hash = await require('bcryptjs').hash(entry.password!, 10);
      break;
    default:
      throw new Error('unknown HtpasswdAlgorithm');
  }

  return `${entry.username}:${hash}`;
}
